/**
 * App Launcher Modification Agent
 *
 * This Frida agent modifies the Android launcher to add custom applications
 * with custom icons and names. It hooks into the launcher's app list management
 * to inject configured apps and replace their visual representation.
 *
 * Features:
 * - Add custom apps to the launcher's all apps list
 * - Replace app icons with custom bitmaps
 * - Localize app names based on language configuration
 * - Replace navigation bar icons
 * - Handle custom click listeners for app launching
 *
 * @module app-launcher-mod
 */

import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './app-launcher-log.js';

import {
    LANGUAGE_CONFIG_PATH,
    APP_CONFIG_PATH,
    loadConfig,
    parseAppConfig,
    runAgent,
    registerClassSafe,
    scheduleOnMainThreadSafe,
    getFieldValue,
} from '../lib/utils.js';

const logger = new Logger('app-launcher-mod');

let AppLauncher = null;
let AllAppAdapter = null;
let StringClass = null;
let ActivityThread = null;
let BitmapDrawable = null;
let NavigationBar = null;
let R_id = null;
let AllAppDataManager = null;
let AppBean = null;
let PackageManager = null;
let AllAppBarView = null;

let config = null;
let languageConfig = null;
let customDrawables = {};
let clickAppListenerMap = {};

let CustomClickListener = null;
let NavClickListener = null;

/**
 * Determines the language index based on locale configuration.
 *
 * Maps language codes to array indices for localized app names:
 * - 'EN': index 0 (English)
 * - 'RU': index 1 (Russian)
 * - Default: index 0 (English)
 *
 * @param {string} locale - Language locale code (e.g., 'EN', 'RU', 'EU')
 * @returns {number} Language index (0 for EN, 1 for RU, 0 for others)
 *
 * @example
 * getLanguageIndex('EN'); // returns 0
 * getLanguageIndex('RU'); // returns 1
 * getLanguageIndex('EU'); // returns 0
 */
function getLanguageIndex(locale) {
    if (!locale) return 0;
    if (locale === 'EN') return 0;
    if (locale === 'RU') return 1;
    return 0;
}

/**
 * Filters and returns new apps that should be added to the launcher.
 *
 * Compares the configured apps against existing packages and returns
 * only those apps that are not already present in the launcher.
 *
 * @param {Object} existingPackages - Map of existing package names (keys are package names)
 * @param {Array<Object>} configApps - Array of app configurations to add
 * @param {string} configApps[].package - Package name of the app
 * @returns {Array<Object>} Array of apps that need to be added
 *
 * @example
 * const existing = { 'com.example.app1': true };
 * const config = [
 *   { package: 'com.example.app1' },
 *   { package: 'com.example.app2' }
 * ];
 * filterNewApps(existing, config); // returns [{ package: 'com.example.app2' }]
 */
function filterNewApps(existingPackages, configApps) {
    if (!existingPackages || !configApps) return [];
    if (!Array.isArray(configApps)) return [];

    return configApps.filter(
        (app) => !Object.prototype.hasOwnProperty.call(existingPackages, app.package)
    );
}

/**
 * Launches an Android application by package name.
 *
 * Creates a launch intent for the specified package and starts the app
 * with the FLAG_ACTIVITY_NEW_TASK flag.
 *
 * @param {string} packageName - Android package name to launch
 *
 * @example
 * startApp('com.example.myapp');
 */
function startApp(packageName) {
    const context = ActivityThread.currentApplication().getApplicationContext();
    const intent = PackageManager.getLaunchIntentForPackage(packageName);
    intent.addFlags(0x10000000); // FLAG_ACTIVITY_NEW_TASK

    AppLauncher.startApp(context, intent, 0);
    logger.info(`${INFO.APP_LAUNCHED} ${packageName}`);
}

/**
 * Creates a cache of custom drawable icons for configured apps.
 *
 * Converts bitmap images from the config into BitmapDrawable objects
 * for both big (all apps view) and small (navigation bar) icons.
 *
 * @returns {Object} Map of package names to [bigDrawable, smallDrawable] arrays
 *
 * @example
 * const cache = createIconCache();
 * // cache = { 'com.example.app': [bigDrawable, smallDrawable] }
 */
function createIconCache() {
    let result = {};
    if (config) {
        const context = ActivityThread.currentApplication().getApplicationContext();
        const resources = context.getResources();

        config.apps.forEach((app) => {
            let drawableBig = null;
            let drawableSmall = null;
            if (app.icon_big) {
                drawableBig = BitmapDrawable.$new
                    .overload('android.content.res.Resources', 'android.graphics.Bitmap')
                    .call(BitmapDrawable, resources, app.icon_big);
            }
            if (app.icon_small) {
                drawableSmall = BitmapDrawable.$new
                    .overload('android.content.res.Resources', 'android.graphics.Bitmap')
                    .call(BitmapDrawable, resources, app.icon_small);
            }
            result[app.package] = [drawableBig, drawableSmall];
        });

        logger.debug(DEBUG.BITMAPS_CREATED);
        return result;
    }
    return result;
}

/**
 * Adds custom applications to the launcher's app list.
 *
 * Collects existing packages to avoid duplicates, then adds configured apps
 * that are installed on the device but not yet in the launcher.
 *
 * @param {Object} originalApps - Java ArrayList of existing AppBean objects
 *
 * @example
 * addCustomApp(allAppsList);
 */
function addCustomApp(originalApps) {
    // Collect existing packages to avoid duplicates
    const existingPackages = {};
    for (let i = 0; i < originalApps.size(); i++) {
        const appBean = Java.cast(originalApps.get(i), AppBean);
        existingPackages[appBean.getPackageName()] = true;
    }

    // Add configured applications that aren't already present
    const newApps = filterNewApps(existingPackages, config.apps);

    newApps.forEach((configApp) => {
        try {
            PackageManager.getPackageInfo(configApp.package, 0);

            logger.debug(`${DEBUG.ADDING_TO_ALL_APPS} ${configApp.package}`);

            const bean = AppBean.$new(2131230851, 2131820622, configApp.package);
            bean.setSubType(configApp.package_sub_type);

            originalApps.add(bean);
        } catch (e) {
            if (e.message?.includes('NameNotFoundException')) {
                logger.debug(`${DEBUG.APP_NOT_INSTALLED} ${configApp.package}`);
            } else {
                logger.error(`${ERROR.GENERIC} ${e.message}`);
            }
        }
    });
}

/**
 * Patches navigation bar icons to replace original apps with custom ones.
 *
 * Searches for NavigationBar instances and replaces configured apps
 * in the navigation bar with custom packages, icons, and click listeners.
 *
 * @example
 * patchNavigationIcons();
 */
function patchNavigationIcons() {
    Java.choose(NavigationBar.$className, {
        onMatch: function (instance) {
            logger.debug(`${DEBUG.NAVIGATION_BAR_FOUND} ${getFieldValue(instance, 'mScreenId')}`);

            if (getFieldValue(instance, 'mScreenId') !== 0) return;

            const mScreenUpItemView1 = getFieldValue(instance, 'mScreenUpItemView1');
            const mScreenUpItemView2 = getFieldValue(instance, 'mScreenUpItemView2');

            [mScreenUpItemView1, mScreenUpItemView2].forEach((button) => {
                if (!button) return;

                const tagPackage = button.getTag(getFieldValue(R_id, 'screen_up_item_package'));
                if (!tagPackage) return;

                const packageName = tagPackage.toString();
                const customApp = config.apps.find(
                    (app) => app.original_package.includes(packageName) && app.replace_bar
                );

                if (!customApp) return;

                try {
                    PackageManager.getPackageInfo(customApp.package, 0);
                    logger.debug(`${DEBUG.REPLACING_ICON} ${packageName} → ${customApp.package}`);

                    button.setOnClickListener(NavClickListener.$new());

                    button.setTag(getFieldValue(R_id, 'screen_up_item_package'), customApp.package);
                    button.setTag(
                        getFieldValue(R_id, 'screen_up_item_app_sub_type'),
                        customApp.package_sub_type
                    );

                    if (customDrawables[customApp.package]) {
                        button.setBackground(customDrawables[customApp.package][1]);
                    }
                } catch (e) {
                    if (e.message?.includes('NameNotFoundException')) {
                        logger.debug(`${DEBUG.APP_NOT_INSTALLED} ${customApp.package}`);
                    } else {
                        logger.error(`${ERROR.GENERIC} ${e.message}`);
                    }
                }
            });
        },
        onComplete: function () {
            logger.debug(DEBUG.NAVIGATION_SEARCH_COMPLETED);
        },
    });
}

/**
 * Updates the main apps list and notifies listeners.
 *
 * Modifies the launcher's main app list by adding custom apps,
 * patching navigation icons, and triggering UI refresh.
 *
 * @example
 * updateMainApps();
 */
function updateMainApps() {
    scheduleOnMainThreadSafe(() => {
        try {
            const instance = AllAppDataManager.getInstance();
            const mainApps = getFieldValue(instance, 'mMainAllApps'); // Direct access to the list

            addCustomApp(mainApps);
            patchNavigationIcons();

            // Notify listeners of the change
            const listeners = getFieldValue(instance, 'mAllAppDataListeners');
            for (let i = 0; i < listeners.size(); i++) {
                const listenerNative = listeners.get(i);
                if (
                    listenerNative.$className === 'com.qinggan.launcher.base.allapp.AllAppBarView'
                ) {
                    const listener = Java.cast(listenerNative, AllAppBarView);
                    listener.onAppReload();
                }
            }

            logger.debug(DEBUG.MAIN_APPS_UPDATED);
        } catch (e) {
            logger.error(`${ERROR.UPDATING_LIST} ${e.message}`);
        }
    });
}

/**
 * Hooks into AllAppDataManager.getAllApps to inject custom apps.
 *
 * Intercepts calls to getAllApps and adds configured custom apps
 * to the returned list for screen 0 (main screen).
 *
 * @example
 * getAllAppsHook();
 */
function getAllAppsHook() {
    try {
        AllAppDataManager.getAllApps.overload('int').implementation = function (screenId) {
            logger.debug(`${DEBUG.GET_ALL_APPS_CALLED} ${screenId}`);
            const originalApps = AllAppDataManager.getAllApps
                .overload('int')
                .call(AllAppDataManager, screenId);

            if (screenId > 0 || !config) return originalApps; // Use cache for other screens
            addCustomApp(originalApps);

            return originalApps;
        };
        logger.debug(DEBUG.GET_ALL_APPS_HOOK_INSTALLED);
    } catch (e) {
        logger.error(`${ERROR.GET_ALL_APPS_HOOK} ${e.message}`);
    }
}

/**
 * Hooks into AllAppAdapter.onBindViewHolder to customize app icons and names.
 *
 * Intercepts the view binding process to replace icons and names for
 * configured custom apps in the all apps view.
 *
 * @example
 * onBindViewHolderHook();
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
                const packageName = appBean.getPackageName();

                if (!packageName || packageName === '') return;

                if (Object.prototype.hasOwnProperty.call(customDrawables, packageName)) {
                    const iconView = getFieldValue(viewHolder, 'iconView');
                    const textView = getFieldValue(viewHolder, 'nameView');
                    const itemView = getFieldValue(viewHolder, 'itemView');

                    const customApp = config.apps.find((app) => app.package === packageName);

                    iconView.setBackground
                        .overload('android.graphics.drawable.Drawable')
                        .call(iconView, customDrawables[packageName][0]);

                    const languageIndex = getLanguageIndex(
                        languageConfig ? languageConfig.language : null
                    );
                    textView.setText(StringClass.$new(customApp.name[languageIndex]));

                    let customClickAppListener = null;
                    if (Object.prototype.hasOwnProperty.call(clickAppListenerMap, packageName)) {
                        customClickAppListener = clickAppListenerMap[packageName];
                    } else {
                        customClickAppListener = CustomClickListener.$new();
                        clickAppListenerMap[packageName] = customClickAppListener;
                    }

                    itemView.setOnClickListener(customClickAppListener);
                }
            } catch (e) {
                logger.error(`${ERROR.ON_BIND_VIEW_HOLDER} ${e.message}`);
                logger.error(e.stack);
            }
        };

        logger.debug(DEBUG.ON_BIND_VIEW_HOLDER_HOOK_INSTALLED);
    } catch (e) {
        logger.error(`${ERROR.ON_BIND_VIEW_HOLDER_HOOK} ${e.message}`);
    }
}

/**
 * Hooks into NavigationBar.updateTheme to patch navigation icons.
 *
 * Intercepts theme updates to ensure custom navigation icons
 * are applied after theme changes.
 *
 * @example
 * updateThemeHook();
 */
function updateThemeHook() {
    try {
        NavigationBar.updateTheme.implementation = function () {
            logger.debug(DEBUG.UPDATE_THEME_CALLED);

            // Call original behavior first
            this.updateTheme.call(this);

            // Then apply our custom icon replacements
            patchNavigationIcons();
        };
    } catch (e) {
        logger.error(`${ERROR.NAVIGATION_BAR_HOOKS} ${e.message}`);
    }
}

/**
 * Initializes Java classes and registers custom click listeners.
 *
 * Sets up all required Java class references and creates custom
 * OnClickListener implementations for app launching.
 *
 * @example
 * init();
 */
function init() {
    AppLauncher = Java.use('com.qinggan.launcher.base.utils.AppLauncher');
    AllAppAdapter = Java.use('com.qinggan.launcher.base.adapter.AllAppAdapter');
    StringClass = Java.use('java.lang.String');
    ActivityThread = Java.use('android.app.ActivityThread');
    BitmapDrawable = Java.use('android.graphics.drawable.BitmapDrawable');
    NavigationBar = Java.use('com.qinggan.mainlauncher.navigation.NavigationBar');
    R_id = Java.use('com.qinggan.mainlauncher.R$id');
    AllAppDataManager = Java.use('com.qinggan.launcher.base.allapp.AllAppDataManager');
    AppBean = Java.use('com.qinggan.launcher.base.bean.AppBean');
    PackageManager = ActivityThread.currentApplication().getPackageManager();
    AllAppBarView = Java.use('com.qinggan.launcher.base.allapp.AllAppBarView');

    const View$OnClickListener = Java.use('android.view.View$OnClickListener');

    CustomClickListener = registerClassSafe(
        {
            name: 'com.qinggan.frida.CustomClickListener',
            implements: [View$OnClickListener],
            methods: {
                onClick: function (view) {
                    try {
                        // Get AppBean from tag
                        const appBeanNative = view.getTag();
                        const appBean = Java.cast(appBeanNative, AppBean);

                        if (appBean) {
                            const packageName = appBean.getPackageName();
                            logger.debug(`${DEBUG.CLICK_ON} ${packageName}`);

                            startApp(packageName);
                        }
                    } catch (e) {
                        logger.error(`${ERROR.CUSTOM_CLICK} ${e.message}`);
                    }
                },
            },
        },
        'ru.voboost.stub.ClickListener',
        logger
    );

    NavClickListener = registerClassSafe(
        {
            name: 'com.qinggan.frida.NavClickListener',
            implements: [View$OnClickListener],
            methods: {
                onClick: function (view) {
                    try {
                        const tagPkg = view.getTag(getFieldValue(R_id, 'screen_up_item_package'));
                        if (!tagPkg) return;

                        const packageName = tagPkg.toString();
                        startApp(packageName);
                    } catch (e) {
                        logger.error(`${ERROR.NAV_CLICK} ${e.message}`);
                    }
                },
            },
        },
        'ru.voboost.stub.ClickListener',
        logger
    );
}

/**
 * Main entry point for the app launcher modification agent.
 * Loads configuration, initializes hooks, and starts the agent.
 */
function main() {
    logger.info(INFO.STARTING);

    init();

    // Load app config with full parameter support
    // Priority: 1) params.config, 2) params.configPath, 3) APP_CONFIG_PATH
    const appContent = loadConfig(APP_CONFIG_PATH, logger);
    config = parseAppConfig(JSON.stringify(appContent));

    // Config is required for this agent
    if (!config) {
        logger.error(ERROR.CONFIG_NOT_AVAILABLE);
        return;
    }

    // Load language config with full parameter support
    // Priority: 1) params.config, 2) params.configPath, 3) LANGUAGE_CONFIG_PATH
    languageConfig = loadConfig(LANGUAGE_CONFIG_PATH, logger);

    // Create icon cache at startup
    customDrawables = createIconCache();

    getAllAppsHook();
    onBindViewHolderHook();
    updateThemeHook();
    // Modify the standard app list
    updateMainApps();

    logger.info(INFO.STARTED);
}

runAgent(main);

// Export for testing
export { getLanguageIndex, filterNewApps };
