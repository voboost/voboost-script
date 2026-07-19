/**
 * Launcher AllApps Modification Agent
 *
 * Injects ALL user-installed applications into the car launcher's app list
 * on every screen. The launcher normally only shows a hardcoded set of
 * system apps — this agent bypasses that restriction.
 *
 * Features:
 * - Discovers all user-installed apps via PackageManager on every screen
 * - Loads icons theme-aware: reads persist.sys.qg.currenttheme, picks
 *   mipmap-night/ic_launcher for dark (default) or mipmap/ic_launcher for
 *   light (simple/golden) directly from the app's APK via AssetManager;
 *   falls back to PackageManager.getApplicationIcon() when the preferred
 *   variant is absent (most third-party APKs ship a single icon).
 * - Loads app labels via PackageManager.getApplicationLabel()
 * - Handles click events to launch third-party apps
 *
 * @module launcher-allapps-mod
 */

import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './launcher-allapps-log.js';

import { runAgent, registerClassSafe, getFieldValue } from '../lib/utils.js';

const logger = new Logger('launcher-allapps-mod');

// Manifest metadata consumed by the manifest generator. `process` is the
// Android process the daemon injects this agent into; `boot:false` = inject
// as soon as the target is reachable (spawn gating handles earliest reach;
// no boot gate needed). Replaces app-launcher for the all-apps list; not
// enabled at the same time as app-launcher (same hook targets).
export const AGENT_META = {
    id: 'launcher-allapps',
    process: 'com.qinggan.app.launcher',
    boot: false,
};

// Java class references (initialized in init())
let ActivityThread = null;
let AppBean = null;
let AllAppDataManager = null;
let AllAppAdapter = null;
let PackageManager = null;
let StringClass = null;
let SystemProperties = null;
let AssetManagerClass = null;
let ResourcesClass = null;

// State
let iconCache = {};
let labelCache = {};
// AssetManager instances backing themed drawables currently in iconCache,
// keyed by packageName. Tracked so they can be explicitly closed (native
// resource cleanup) when iconCache is invalidated on theme change.
let iconAssetManagers = {};
let cachedTheme = null;
let clickListenerFactory = null;
let clickAppListenerMap = {};

// Cache of all installed launchable user apps (raw, unfiltered against the
// launcher's existing package list). PackageManager.getInstalledApplications()
// plus a getLaunchIntentForPackage() call per package is expensive and runs on
// the UI thread; the installed package set rarely changes during a session,
// so we compute this once and reuse it across all getAllApps() calls.
let cachedInstalledApps = null;

// Android constants
const FLAG_SYSTEM = 0x00000001;

/**
 * Packages that should never appear in the launcher.
 */
export const EXCLUDED_PACKAGES = {
    'com.qinggan.app.launcher': true,
    'ru.voboost.inject': true,
};

/**
 * Checks if an ApplicationInfo represents a user-installed (non-system) app.
 *
 * @param {number} flags - ApplicationInfo.flags value
 * @param {boolean} hasLaunchIntent - Whether the app has a launch intent
 * @returns {boolean} True if the app is a user-installed launchable app
 */
export function isUserApp(flags, hasLaunchIntent) {
    if (!hasLaunchIntent) return false;
    return (flags & FLAG_SYSTEM) === 0;
}

/**
 * Filters installed apps to find launchable user apps not already in the launcher.
 *
 * @param {Object} existingPackages - Map of package names already in launcher
 * @param {Array<Object>} installedApps - Array of {packageName, flags, hasLaunchIntent}
 * @param {Object} [excludedPackages] - Map of package names to always exclude
 * @returns {Array<string>} Package names of new launchable user apps
 */
export function filterLaunchableApps(existingPackages, installedApps, excludedPackages = {}) {
    if (!existingPackages || !installedApps || !Array.isArray(installedApps)) return [];

    return installedApps
        .filter((app) => {
            if (!app || !app.packageName) return false;
            if (Object.prototype.hasOwnProperty.call(existingPackages, app.packageName)) {
                return false;
            }
            if (
                excludedPackages &&
                Object.prototype.hasOwnProperty.call(excludedPackages, app.packageName)
            ) {
                return false;
            }
            return isUserApp(app.flags, app.hasLaunchIntent);
        })
        .map((app) => app.packageName);
}

/**
 * Reads the current launcher theme from system properties.
 *
 * @returns {string} "default", "simple", or "golden"
 */
function getCurrentTheme() {
    try {
        return SystemProperties.get('persist.sys.qg.currenttheme', 'default');
    } catch {
        return 'default';
    }
}

/**
 * Checks if the icon cache should be invalidated due to theme change.
 * Clears the cache when the theme has changed since last check.
 *
 * @returns {string} The current theme (so callers don't need a second
 *   getCurrentTheme() call).
 */
function checkThemeChange() {
    const theme = getCurrentTheme();
    if (cachedTheme !== null && cachedTheme !== theme) {
        logger.debug(DEBUG.THEME_CHANGED + ' ' + cachedTheme + ' -> ' + theme);
        closeIconAssetManagers();
        iconCache = {};
    }
    cachedTheme = theme;
    return theme;
}

/**
 * Closes all AssetManager instances backing currently-cached themed icons,
 * and clears the tracking map. Called whenever iconCache is invalidated so
 * the native AssetManager/Resources objects don't leak.
 */
function closeIconAssetManagers() {
    for (const packageName of Object.keys(iconAssetManagers)) {
        try {
            iconAssetManagers[packageName].close();
        } catch {
            // ignore close() errors — nothing more we can do
        }
    }
    iconAssetManagers = {};
}

/**
 * Tries to load a themed icon from an APK by directly accessing its resources
 * via AssetManager.
 *
 * For dark theme (default): prefers mipmap-night/ic_launcher, falls back to mipmap.
 * For light theme (simple/golden): prefers mipmap/ic_launcher, falls back to mipmap-night.
 *
 * Most third-party APKs have only mipmap (no mipmap-night), so the same icon
 * is returned regardless of theme. For APKs that ship both variants (like
 * voboost), the correct one is selected.
 *
 * The returned Drawable stays backed by a live AssetManager for as long as
 * it remains cached in iconCache — the caller is responsible for tracking
 * and closing that AssetManager (see iconAssetManagers) once the cache
 * entry is invalidated. AssetManagers created here that DON'T end up
 * backing a returned drawable are closed immediately.
 *
 * @param {string} packageName - Android package name
 * @param {string} theme - Current theme, as returned by getCurrentTheme()/checkThemeChange()
 * @returns {{drawable: Object, assetManager: Object}|null} Drawable + the
 *   AssetManager backing it, or null if loading failed
 */
function loadThemedIconFromApk(packageName, theme) {
    let assetManager = null;
    try {
        const appInfo = PackageManager.getApplicationInfo(packageName, 0);
        const apkPath = appInfo.sourceDir;

        // Create a new AssetManager and add the APK path.
        // addAssetPath is a public method, so it can be called directly —
        // no reflection needed. Its result is a boxed Integer, so unbox via
        // Number() before comparing (a direct `=== 0` check is always false).
        assetManager = AssetManagerClass.$new();
        const added = assetManager.addAssetPath(apkPath);
        if (Number(added) === 0) {
            assetManager.close();
            return null;
        }

        // Create Resources from this AssetManager
        const context = ActivityThread.currentApplication().getApplicationContext();
        const dm = context.getResources().getDisplayMetrics();
        const config = context.getResources().getConfiguration();
        const resources = ResourcesClass.$new(assetManager, dm, config);

        // Determine resource name priority based on theme
        const darkTheme = theme === 'default';
        const prefixes = darkTheme ? ['mipmap-night', 'mipmap'] : ['mipmap', 'mipmap-night'];

        for (const prefix of prefixes) {
            for (const iconName of ['ic_launcher', 'ic_launcher_round']) {
                const resId = resources.getIdentifier(iconName, prefix, packageName);
                if (resId !== 0) {
                    try {
                        const drawable = resources.getDrawable(resId);
                        if (drawable) {
                            const msg = darkTheme
                                ? DEBUG.ICON_LOADED_APK_NIGHT
                                : DEBUG.ICON_LOADED_APK_DEFAULT;
                            logger.debug(
                                msg + ' ' + packageName + ' (' + prefix + '/' + iconName + ')'
                            );
                            // Caller takes ownership of assetManager now.
                            return { drawable, assetManager };
                        }
                    } catch {
                        // Resource exists but can't be loaded as drawable, try next
                    }
                }
            }
        }

        // No themed variant found in this APK — nothing to keep this
        // AssetManager open for.
        assetManager.close();
        return null;
    } catch (e) {
        // Genuine failure (e.g. AssetManager/PackageManager error), as opposed
        // to simply not finding a themed variant (handled above by falling
        // through to the PackageManager icon fallback).
        logger.error(ERROR.ICON_LOAD + ' ' + packageName + ': ' + e.message);
        if (assetManager) {
            try {
                assetManager.close();
            } catch {
                // ignore close() errors — nothing more we can do
            }
        }
        return null;
    }
}

/**
 * Loads an app icon using a cascade of strategies.
 * Checks theme change and clears cache if needed.
 *
 * @param {string} packageName - Android package name
 * @returns {Object|null} Java Drawable object, or null if loading failed
 */
function loadAppIcon(packageName) {
    const theme = checkThemeChange();

    // Check cache first
    if (Object.prototype.hasOwnProperty.call(iconCache, packageName)) {
        return iconCache[packageName];
    }

    let drawable = null;

    // Strategy 1: Themed icon from APK via AssetManager
    const themed = loadThemedIconFromApk(packageName, theme);
    if (themed) {
        drawable = themed.drawable;
        iconAssetManagers[packageName] = themed.assetManager;
    }

    // Strategy 2: PackageManager.getApplicationIcon fallback
    if (!drawable) {
        try {
            drawable = PackageManager.getApplicationIcon(packageName);
            if (drawable) {
                logger.debug(DEBUG.ICON_LOADED_PM + ' ' + packageName);
            }
        } catch (e) {
            logger.debug(DEBUG.ICON_LOAD_FAILED + ' ' + packageName + ': ' + e.message);
        }
    }

    // Only cache successful loads. A transient failure isn't cached so a
    // later call can retry (and possibly succeed once whatever caused the
    // failure clears up).
    if (drawable) {
        iconCache[packageName] = drawable;
    }
    return drawable;
}

/**
 * Loads an application label using PackageManager.getApplicationLabel().
 *
 * @param {string} packageName - Android package name
 * @returns {string|null} App display name, or null if loading failed
 */
function loadAppLabel(packageName) {
    if (Object.prototype.hasOwnProperty.call(labelCache, packageName)) {
        return labelCache[packageName];
    }

    let label = null;
    try {
        const appInfo = PackageManager.getApplicationInfo(packageName, 0);
        label = PackageManager.getApplicationLabel(appInfo).toString();
        logger.debug(DEBUG.APP_LABEL_LOADED + ' ' + packageName + ' -> ' + label);
    } catch (e) {
        logger.debug(DEBUG.ICON_LOAD_FAILED + ' ' + packageName + ': ' + e.message);
    }

    // Only cache successful loads, so a transient failure can be retried later.
    if (label) {
        labelCache[packageName] = label;
    }
    return label;
}

/**
 * Launches an Android application by package name.
 *
 * @param {string} packageName - Android package name to launch
 */
function startApp(packageName) {
    try {
        const context = ActivityThread.currentApplication().getApplicationContext();
        const intent = PackageManager.getLaunchIntentForPackage(packageName);
        if (!intent) {
            logger.error(ERROR.PACKAGE_NOT_FOUND + ' ' + packageName);
            return;
        }
        intent.addFlags(0x10000000); // FLAG_ACTIVITY_NEW_TASK
        context.startActivity(intent);
        logger.info(INFO.APP_LAUNCHED + ' ' + packageName);
    } catch (e) {
        logger.error(ERROR.APP_LAUNCH + ' ' + e.message);
    }
}

/**
 * Collects existing package names from the launcher's app list.
 *
 * @param {Object} appList - Java ArrayList of AppBean objects
 * @returns {Object} Map of package name -> true
 */
function collectExistingPackages(appList) {
    const existing = {};
    for (let i = 0; i < appList.size(); i++) {
        try {
            const appBean = Java.cast(appList.get(i), AppBean);
            const pkg = appBean.getPackageName();
            if (pkg) existing[pkg] = true;
        } catch {
            // Skip entries that can't be cast
        }
    }
    return existing;
}

/**
 * Queries PackageManager for all installed applications, once, and returns
 * a plain-data snapshot ({packageName, flags, hasLaunchIntent}) suitable for
 * filterLaunchableApps(). The result is cached at module scope: a full
 * PackageManager.getInstalledApplications(0) scan plus a
 * getLaunchIntentForPackage() call per installed package is expensive and
 * runs on the UI thread, and getAllApps() (which drives this) can be called
 * repeatedly (e.g. on every screen render/refresh). The installed package
 * set doesn't change meaningfully during a single agent session, so
 * computing this once and reusing it is sufficient — no invalidation logic
 * is needed.
 *
 * @returns {Array<Object>} Snapshot of installed applications
 */
function getInstalledAppsSnapshot() {
    if (cachedInstalledApps !== null) return cachedInstalledApps;

    const context = ActivityThread.currentApplication().getApplicationContext();
    const pm = context.getPackageManager();

    const installed = pm.getInstalledApplications(0);
    const snapshot = [];

    for (let i = 0; i < installed.size(); i++) {
        const appInfo = installed.get(i);
        const packageName = appInfo.packageName.toString();
        const flags = getFieldValue(appInfo, 'flags');
        const hasLaunchIntent = !!pm.getLaunchIntentForPackage(packageName);

        snapshot.push({ packageName, flags, hasLaunchIntent });
    }

    cachedInstalledApps = snapshot;
    return cachedInstalledApps;
}

/**
 * Returns user-installed, launchable apps not already in the launcher, by
 * combining the (cached) installed-apps snapshot with the shared
 * filterLaunchableApps() helper — the same helper covered by unit tests —
 * so the real runtime path exercises tested logic, including
 * EXCLUDED_PACKAGES filtering.
 *
 * @param {Object} existingPackages - Map of packages already in launcher
 * @returns {Array<string>} Package names of new apps to add
 */
function discoverNewApps(existingPackages) {
    const installedApps = getInstalledAppsSnapshot();
    const newApps = filterLaunchableApps(existingPackages, installedApps, EXCLUDED_PACKAGES);

    logger.debug(DEBUG.INSTALLED_APPS_FOUND + ' ' + newApps.length);
    return newApps;
}

/**
 * Adds discovered user apps to the launcher's app list.
 *
 * @param {Object} originalApps - Java ArrayList of AppBean objects
 */
function addUserApps(originalApps) {
    const existingPackages = collectExistingPackages(originalApps);
    const newApps = discoverNewApps(existingPackages);

    let added = 0;
    for (const packageName of newApps) {
        try {
            const bean = AppBean.$new(0, 0, packageName);
            bean.setSubType(packageName);
            originalApps.add(bean);
            added++;
        } catch (e) {
            logger.error(ERROR.GET_ALL_APPS_HOOK + ' ' + packageName + ': ' + e.message);
        }
    }

    if (added > 0) {
        logger.debug(DEBUG.APPS_ADDED + ' ' + added);
    }
}

/**
 * Hooks AllAppDataManager.getAllApps to inject user-installed apps
 * on every screen.
 */
function getAllAppsHook() {
    try {
        AllAppDataManager.getAllApps.overload('int').implementation = function (screenId) {
            logger.debug(DEBUG.GET_ALL_APPS_CALLED + ' ' + screenId);

            const originalApps = AllAppDataManager.getAllApps
                .overload('int')
                .call(AllAppDataManager, screenId);

            // Inject on all screens (0 = driver, 1 = passenger)
            addUserApps(originalApps);

            return originalApps;
        };
        logger.debug(DEBUG.HOOK_INSTALLED + ' getAllApps');
    } catch (e) {
        logger.error(ERROR.GET_ALL_APPS_HOOK + ' ' + e.message);
    }
}

/**
 * Hooks AllAppAdapter.onBindViewHolder to set custom icons, labels, and
 * click listeners for injected third-party apps.
 */
function onBindViewHolderHook() {
    try {
        AllAppAdapter.onBindViewHolder.overload(
            'com.qinggan.launcher.base.adapter.AllAppAdapter$AppViewHolder',
            'int'
        ).implementation = function (viewHolder, position) {
            // Call original implementation first
            this.onBindViewHolder
                .overload('com.qinggan.launcher.base.adapter.AllAppAdapter$AppViewHolder', 'int')
                .call(this, viewHolder, position);

            try {
                const mAppBeans = getFieldValue(this, 'mAppBeans');
                if (!mAppBeans) return;

                const size = mAppBeans.size();
                if (position < 0 || position >= size) return;

                const appBeanNative = mAppBeans.get.overload('int').call(mAppBeans, position);
                if (!appBeanNative) return;

                const appBean = Java.cast(appBeanNative, AppBean);

                // Only process custom apps (icon == 0)
                const iconResId = appBean.getIcon();
                if (iconResId !== 0) return;

                const packageName = appBean.getPackageName();
                if (!packageName || packageName === '') return;

                logger.debug(DEBUG.ON_BIND_VIEW_HOLDER + ' ' + position + ' (' + packageName + ')');

                // Set icon
                const drawable = loadAppIcon(packageName);
                if (drawable) {
                    const iconView = getFieldValue(viewHolder, 'iconView');
                    if (iconView) {
                        iconView.setBackground
                            .overload('android.graphics.drawable.Drawable')
                            .call(iconView, drawable);
                    }
                }

                // Set label
                const label = loadAppLabel(packageName);
                if (label) {
                    const textView = getFieldValue(viewHolder, 'nameView');
                    if (textView) {
                        textView.setText(StringClass.$new(label));
                    }
                }

                // Set click listener — reuse a cached listener per package
                // instead of creating a new one on every bind (this hook
                // fires repeatedly while the list scrolls).
                const itemView = getFieldValue(viewHolder, 'itemView');
                if (itemView) {
                    let listener;
                    if (Object.prototype.hasOwnProperty.call(clickAppListenerMap, packageName)) {
                        listener = clickAppListenerMap[packageName];
                    } else {
                        listener = clickListenerFactory.$new(packageName);
                        clickAppListenerMap[packageName] = listener;
                    }
                    itemView.setOnClickListener(listener);
                }
            } catch (e) {
                logger.error(ERROR.ON_BIND_HOOK + ' ' + e.message);
            }
        };

        logger.debug(DEBUG.HOOK_INSTALLED + ' onBindViewHolder');
    } catch (e) {
        logger.error(ERROR.ON_BIND_HOOK + ' ' + e.message);
    }
}

/**
 * Initializes Java class references and registers custom classes.
 *
 * @returns {boolean} True on success, false if initialization failed (e.g.
 *   a required class doesn't exist on this firmware)
 */
function init() {
    try {
        ActivityThread = Java.use('android.app.ActivityThread');
        AppBean = Java.use('com.qinggan.launcher.base.bean.AppBean');
        AllAppDataManager = Java.use('com.qinggan.launcher.base.allapp.AllAppDataManager');
        AllAppAdapter = Java.use('com.qinggan.launcher.base.adapter.AllAppAdapter');
        StringClass = Java.use('java.lang.String');
        SystemProperties = Java.use('android.os.SystemProperties');
        AssetManagerClass = Java.use('android.content.res.AssetManager');
        ResourcesClass = Java.use('android.content.res.Resources');

        const context = ActivityThread.currentApplication().getApplicationContext();
        PackageManager = context.getPackageManager();

        // Register click listener that stores packageName in instance field
        const ViewOnClickListener = Java.use('android.view.View$OnClickListener');

        clickListenerFactory = registerClassSafe(
            {
                name: 'com.voboost.frida.AllAppsClickListener',
                implements: [ViewOnClickListener],
                methods: {
                    onClick: {
                        returnType: 'void',
                        argumentTypes: ['android.view.View'],
                        implementation: function () {
                            try {
                                const pkg = this.packageName.value;
                                if (pkg) {
                                    startApp(pkg.toString());
                                }
                            } catch (e) {
                                logger.error(ERROR.APP_LAUNCH + ' ' + e.message);
                            }
                        },
                    },
                },
                fields: {
                    packageName: 'java.lang.String',
                },
            },
            'ru.voboost.stub.ClickListener',
            logger
        );

        // Patch $new to accept packageName and store it on the constructed
        // instance. NOTE: inside a Frida $new override, `this` refers to the
        // class wrapper, NOT the object being constructed — `instance` is the
        // one whose `.packageName.value` onClick() will actually read.
        const originalNew = clickListenerFactory.$new;
        clickListenerFactory.$new = function (packageName) {
            const instance = originalNew.call(clickListenerFactory);
            instance.packageName.value = packageName;
            return instance;
        };

        return true;
    } catch (e) {
        logger.error(ERROR.INIT_FAILED + ' ' + e.message);
        return false;
    }
}

/**
 * Main entry point for the launcher allapps modification agent.
 */
export function main() {
    logger.info(INFO.STARTING);

    if (!init()) {
        return;
    }

    getAllAppsHook();
    onBindViewHolderHook();

    logger.info(INFO.STARTED);
}

runAgent(main);
