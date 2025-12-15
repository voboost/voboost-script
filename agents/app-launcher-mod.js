import { Logger } from "../lib/logger.js";

import {
    LANGUAGE_CONFIG_PATH,
    APP_CONFIG_PATH,
    LoadTextFile,
    parseConfig,
    parseAppConfig,
} from "../lib/utils.js";

const logger = new Logger("app-launcher-mod");

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

function startApp(packageName) {
    const context = ActivityThread.currentApplication().getApplicationContext();
    const intent = PackageManager.getLaunchIntentForPackage(packageName);
    intent.addFlags(0x10000000); // FLAG_ACTIVITY_NEW_TASK

    AppLauncher.startApp(context, intent, 0);
    logger.info(`App launched: ${packageName}`);
}

function createIconCache() {
    let result = {};
    if (config) {
        const context = ActivityThread.currentApplication().getApplicationContext();
        const resources = context.getResources();

        config.apps.forEach(app => {
            let drawableBig = null;
            let drawableSmall = null;
            if (app.icon_big) {
                drawableBig = BitmapDrawable.$new.overload("android.content.res.Resources", "android.graphics.Bitmap")
                    .call(BitmapDrawable, resources, app.icon_big);
            }
            if (app.icon_small) {
                drawableSmall = BitmapDrawable.$new.overload("android.content.res.Resources", "android.graphics.Bitmap")
                    .call(BitmapDrawable, resources, app.icon_small);
            }
            result[app.package] = [drawableBig, drawableSmall];
        });

        logger.debug("Bitmaps created");
        return result;
    }
    return result;
}

function addCustomApp(originalApps) {
    // Собираем существующие пакеты
    const existingPackages = {};
    for (let i = 0; i < originalApps.size(); i++) {
        const appBean = Java.cast(originalApps.get(i), AppBean);
        existingPackages[appBean.getPackageName()] = true;
    }
    // Добавляем ваши приложения
    config.apps.forEach(configApp => {

        try {
            if (!Object.prototype.hasOwnProperty.call(existingPackages, configApp.package)) {
                PackageManager.getPackageInfo(configApp.package, 0);

                logger.debug(`Adding to AllApps: ${configApp.package}`);

                const bean = AppBean.$new(2131230851, 2131820622, configApp.package);
                bean.setSubType(configApp.package_sub_type);

                originalApps.add(bean);
                existingPackages[configApp.package] = true;
            }
        } catch (e) {
            if (e.message?.includes("NameNotFoundException")) {
                logger.debug(`App not installed: ${configApp.package}`);
            } else {
                logger.error(`Error: ${e.message}`);
            }
        }
    });
}

function patchNavigationIcons() {
    Java.choose(NavigationBar.$className, {
        onMatch: function (instance) {
            logger.debug(`Found NavigationBar instance, mScreenId = ${instance.mScreenId.value}`);

            if (instance.mScreenId.value !== 0) return;

            const mScreenUpItemView1 = instance.mScreenUpItemView1.value;
            const mScreenUpItemView2 = instance.mScreenUpItemView2.value;

            [mScreenUpItemView1, mScreenUpItemView2].forEach(button => {
                if (!button) return;

                const tagPackage = button.getTag(R_id.screen_up_item_package.value);
                if (!tagPackage) return;

                const packageName = tagPackage.toString();
                const customApp = config.apps.find(app => app.original_package.includes(packageName) && app.replace_bar);

                if (!customApp) return;

                try {
                    PackageManager.getPackageInfo(customApp.package, 0);
                    logger.debug(`Replacing icon for package: ${packageName} → ${customApp.package}`);

                    button.setOnClickListener(NavClickListener.$new());

                    button.setTag(R_id.screen_up_item_package.value, customApp.package);
                    button.setTag(R_id.screen_up_item_app_sub_type.value, customApp.package_sub_type);

                    if (customDrawables[customApp.package]) {
                        button.setBackground(customDrawables[customApp.package][1]);
                    }
                } catch (e) {
                    if (e.message?.includes("NameNotFoundException")) {
                        logger.debug(`App not installed: ${customApp.package}`);
                    } else {
                        logger.error(`Error: ${e.message}`);
                    }
                }

            });
        },
        onComplete: function () {
            logger.debug("NavigationBar search completed");
        },
    });
}

function updateMainApps() {
    Java.scheduleOnMainThread(() => {
        try {
            const instance = AllAppDataManager.getInstance();
            const mainApps = instance.mMainAllApps.value; // ← прямой доступ к списку

            addCustomApp(mainApps);
            patchNavigationIcons();

            // Уведомляем слушателей
            const listeners = instance.mAllAppDataListeners.value;
            for (let i = 0; i < listeners.size(); i++) {
                const listenerNative = listeners.get(i);
                if (listenerNative.$className === "com.qinggan.launcher.base.allapp.AllAppBarView") {
                    const listener = Java.cast(listenerNative, AllAppBarView);
                    listener.onAppReload();
                }
            }

            logger.debug("mMainAllApps updated");
        } catch (e) {
            logger.error(`Error updating list: ${e.message}`);
        }
    });
}

function getLanguageIndex() {
    if (!languageConfig || !languageConfig.language) return 0;
    if (languageConfig.language == "EN") return 0;
    if (languageConfig.language == "RU") return 1;
    return 0;
}

function getAllAppsHook() {
    // --- Хук на AllAppDataManager.getAllApps ---
    try {
        AllAppDataManager.getAllApps.overload("int").implementation = function (screenId) {

            logger.debug(`AllAppDataManager.getAllApps called for screenId: ${screenId}`);
            const originalApps = AllAppDataManager.getAllApps.overload("int").call(AllAppDataManager, screenId);

            if (screenId > 0 || !config) return originalApps; // Используем кэш
            addCustomApp(originalApps);

            return originalApps;
        };
        logger.debug("getAllApps hook installed");
    } catch (e) {
        logger.error(`Error installing getAllApps hook: ${e.message}`);
    }
}

function onBindViewHolderHook() {
    // --- Хук на AllAppAdapter.onBindViewHolder (для иконок в AllAppsView) ---
    try {
        AllAppAdapter.onBindViewHolder.overload("com.qinggan.launcher.base.adapter.AllAppAdapter$AppViewHolder", "int")
            .implementation = function (viewHolder, position) {
                // Сначала вызываем оригинальную реализацию
                this.onBindViewHolder.overload("com.qinggan.launcher.base.adapter.AllAppAdapter$AppViewHolder", "int")
                    .call(this, viewHolder, position);

                try {

                    const mAppBeans = this.mAppBeans.value;
                    if (!mAppBeans) return;

                    const size = mAppBeans.size();
                    if (position < 0 || position >= size) return;

                    const appBeanNative = mAppBeans.get.overload("int").call(mAppBeans, position);
                    if (!appBeanNative) return;

                    const appBean = Java.cast(appBeanNative, AppBean);
                    const packageName = appBean.getPackageName();

                    if (!packageName || packageName === "") return;

                    if (Object.prototype.hasOwnProperty.call(customDrawables, packageName)) {
                        const iconView = viewHolder.iconView.value;
                        const textView = viewHolder.nameView.value;
                        const itemView = viewHolder.itemView.value;

                        const customApp = config.apps.find(app => app.package === packageName);

                        iconView.setBackground.overload("android.graphics.drawable.Drawable")
                            .call(iconView, customDrawables[packageName][0]);

                        const languageIndex = getLanguageIndex();
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
                    logger.error(`Error in onBindViewHolder: ${e.message}`);
                    logger.error(e.stack);
                }
            };

        logger.debug("onBindViewHolder hook installed");
    } catch (e) {
        logger.error(`Error installing onBindViewHolder hook: ${e.message}`);
    }
}

function updateThemeHook() {
    // --- Хук на NavigationBar (для замены иконок и обработки нажатий) ---
    try {
        // --- Хук на initScreenUpViews (для замены иконок и тегов при инициализации) ---
        NavigationBar.updateTheme.implementation = function () {
            logger.debug("NavigationBar.updateTheme() called");

            // Сначала оригинальное поведение
            this.updateTheme.call(this);

            // Затем — наша замена
            patchNavigationIcons();
        };

    } catch (e) {

        logger.error(`Error installing NavigationBar hooks: ${e.message}`);
    }
}

function init() {
    AppLauncher = Java.use("com.qinggan.launcher.base.utils.AppLauncher");
    AllAppAdapter = Java.use("com.qinggan.launcher.base.adapter.AllAppAdapter");
    StringClass = Java.use("java.lang.String");
    ActivityThread = Java.use("android.app.ActivityThread");
    BitmapDrawable = Java.use("android.graphics.drawable.BitmapDrawable");
    NavigationBar = Java.use("com.qinggan.mainlauncher.navigation.NavigationBar");
    R_id = Java.use("com.qinggan.mainlauncher.R$id");
    AllAppDataManager = Java.use("com.qinggan.launcher.base.allapp.AllAppDataManager");
    AppBean = Java.use("com.qinggan.launcher.base.bean.AppBean");
    PackageManager = ActivityThread.currentApplication().getPackageManager();
    AllAppBarView = Java.use("com.qinggan.launcher.base.allapp.AllAppBarView");

    const View$OnClickListener = Java.use("android.view.View$OnClickListener");

    CustomClickListener = Java.registerClass({
        name: "com.qinggan.frida.CustomClickListener",
        implements: [View$OnClickListener],
        methods: {
            onClick: function (view) {
                try {
                    // Получаем AppBean из тега
                    const appBeanNative = view.getTag();
                    const appBean = Java.cast(appBeanNative, AppBean);

                    if (appBean) {
                        const packageName = appBean.getPackageName();
                        logger.debug(`Click on: ${packageName}`);

                        startApp(packageName);

                    }
                } catch (e) {
                    logger.error(`Error in custom click: ${e.message}`);
                }
            },
        },
    });

    NavClickListener = Java.registerClass({
        name: "com.qinggan.frida.NavClickListener",
        implements: [View$OnClickListener],
        methods: {
            onClick: function (view) {
                try {
                    const tagPkg = view.getTag(R_id.screen_up_item_package.value);
                    if (!tagPkg) return;

                    const packageName = tagPkg.toString();
                    startApp(packageName);
                } catch (e) {
                    logger.error(`NavClickListener error: ${e.message}`);
                }
            },
        },
    });
}

function main() {
    // --- Основная логика Frida ---
    init();
    // Загружаем конфиг при старте скрипта
    const appContent = LoadTextFile(APP_CONFIG_PATH);
    config = parseAppConfig(appContent);

    const languageContent = LoadTextFile(LANGUAGE_CONFIG_PATH);
    languageConfig = parseConfig(languageContent);

    // Создаем кэш иконок при старте
    customDrawables = createIconCache();

    getAllAppsHook();
    onBindViewHolderHook();
    updateThemeHook();
    //изминение стандартного списка приложений
    updateMainApps();

    logger.info("App launcher hooks installed");
}

Java.perform(() => { main(); });
