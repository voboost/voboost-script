const LANGUAGE_CONFIG_PATH = "/data/local/tmp/test/language_config.json";
const APP_CONFIG_PATH = "/data/local/tmp/test/apps_config.json";
function LoadTextFile(file) {
    const FileInputStream = Java.use("java.io.FileInputStream");
    const InputStreamReader = Java.use("java.io.InputStreamReader");
    const BufferedReader = Java.use("java.io.BufferedReader");

    const fis = FileInputStream.$new(file);
    const isr = InputStreamReader.$new(fis);
    const reader = BufferedReader.$new(isr);
    let line, content = "";
    while ((line = reader.readLine()) !== null) {
        content += line + "\n";
    }
    reader.close();
    return content;
}
function parseConfig(content) {
    try {
        const config = JSON.parse(content);
        console.log("[+] Конфиг успешно загружен");
        return config;
    } catch (e) {
        console.error("[-] Ошибка загрузки конфига:", e.message);
        return null;
    }
}
function parseAppConfig(content) {
    try {
        const Base64 = Java.use("android.util.Base64");
        const BitmapFactory = Java.use("android.graphics.BitmapFactory");

        console.log("[*] Загрузка конфига: " + APP_CONFIG_PATH);

        //const content = LoadTextFile(APP_CONFIG_PATH);
        const config = JSON.parse(content);

        const items = config.apps.map(obj => {
            const item = {
                package: obj.package,
                name: obj.name || ["", ""],
                icon_big: null,
                icon_small: null,
                replace_bar: obj.replace_bar || false,
                original_package: obj.original_package || [],
                package_sub_type: obj.package_sub_type || "UNDEFINED",
            };

            if (obj.icon_big && obj.icon_big != "") {
                try {
                    const bytes = Base64.decode(obj.icon_big, Base64.DEFAULT.value);
                    item.icon_big = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
                    console.log("[+] Иконка загружена для: " + obj.package);
                } catch (e) {
                    console.log("[-] Ошибка декодирования иконки для " + obj.package);
                }
            }
            if (obj.icon_small && obj.icon_small != "") {
                try {
                    const bytes = Base64.decode(obj.icon_small, Base64.DEFAULT.value);
                    item.icon_small = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
                    console.log("[+] Иконка загружена для: " + obj.package);
                } catch (e) {
                    console.log("[-] Ошибка декодирования иконки для " + obj.package);
                }
            }
            else {
                item.icon_small = item.icon_big;
            }

            return item;
        });

        console.log("[+] Конфиг загружен. Найдено " + items.length + " записей.");
        return { apps: items };

    } catch (e) {
        console.log("[-] Ошибка загрузки конфига: " + e.message);
        return null;
    }
}

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
    console.log("[+] Запущено через AppLauncher.startApp: " + packageName);
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
                drawableBig = BitmapDrawable.$new.overload('android.content.res.Resources', 'android.graphics.Bitmap')
                    .call(BitmapDrawable, resources, app.icon_big);
            }
            if (app.icon_small) {
                drawableSmall = BitmapDrawable.$new.overload('android.content.res.Resources', 'android.graphics.Bitmap')
                    .call(BitmapDrawable, resources, app.icon_small);
            }
            result[app.package] = [drawableBig, drawableSmall];

        });
        console.log("[+] Bitmaps созданы");
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
            if (!existingPackages.hasOwnProperty(configApp.package)) {
                PackageManager.getPackageInfo(configApp.package, 0);

                console.log("[+] Добавление в список AllApps: " + configApp.package);

                const bean = AppBean.$new(2131230851, 2131820622, configApp.package);
                bean.setSubType(configApp.package_sub_type);

                originalApps.add(bean);
                existingPackages[configApp.package] = true;
            }
        }
        catch (e) {
            if (e.message?.includes("NameNotFoundException")) {
                console.log("[-] Приложение не установлено: " + configApp.package);
            } else {
                console.log("[-] Ошибка: " + e.message);
            }
        }
    });
}

function patchNavigationIcons() {
    Java.choose(NavigationBar.$className, {
        onMatch: function (instance) {
            console.log("[*] Найден экземпляр NavigationBar, mScreenId =", instance.mScreenId.value);

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
                    console.log("[+] Замена иконки для пакета:", packageName, "→", customApp.package);

                    button.setOnClickListener(NavClickListener.$new());

                    button.setTag(R_id.screen_up_item_package.value, customApp.package);
                    button.setTag(R_id.screen_up_item_app_sub_type.value, customApp.package_sub_type);

                    if (customDrawables[customApp.package]) {
                        button.setBackground(customDrawables[customApp.package][1]);
                    }
                }
                catch (e) {
                    if (e.message?.includes("NameNotFoundException")) {
                        console.log("[-] Приложение не установлено: " + customApp.package);
                    } else {
                        console.log("[-] Ошибка: " + e.message);
                    }
                }

            });
        },
        onComplete: function () {
            console.log("[*] Поиск NavigationBar завершён");
        }
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

            console.log("[+] mMainAllApps обновлён");
        } catch (e) {
            console.log("[-] Ошибка обновления списка: " + e.message);
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
        AllAppDataManager.getAllApps.overload('int').implementation = function (screenId) {

            console.log("[*] AllAppDataManager.getAllApps вызван для screenId: " + screenId);
            const originalApps = AllAppDataManager.getAllApps.overload('int').call(AllAppDataManager, screenId);

            if (screenId > 0 || !config) return originalApps; // Используем кэш
            addCustomApp(originalApps);

            return originalApps;
        };
        console.log("[*] Frida: Хук на getAllAppsImpl установлен.");
    } catch (e) {
        console.log("[-] Ошибка при установке хука getAllAppsImpl: " + e.message);
    }
}

function onBindViewHolderHook() {
    // --- Хук на AllAppAdapter.onBindViewHolder (для иконок в AllAppsView) ---
    try {
        AllAppAdapter.onBindViewHolder.overload('com.qinggan.launcher.base.adapter.AllAppAdapter$AppViewHolder', 'int')
            .implementation = function (viewHolder, position) {
                // Сначала вызываем оригинальную реализацию
                this.onBindViewHolder.overload('com.qinggan.launcher.base.adapter.AllAppAdapter$AppViewHolder', 'int')
                    .call(this, viewHolder, position);

                try {

                    const mAppBeans = this.mAppBeans.value;
                    if (!mAppBeans) return;

                    const size = mAppBeans.size();
                    if (position < 0 || position >= size) return;

                    const appBeanNative = mAppBeans.get.overload('int').call(mAppBeans, position);
                    if (!appBeanNative) return;

                    const appBean = Java.cast(appBeanNative, AppBean);
                    const packageName = appBean.getPackageName();

                    if (!packageName || packageName === "") return;

                    if (customDrawables.hasOwnProperty(packageName)) {
                        const iconView = viewHolder.iconView.value;
                        const textView = viewHolder.nameView.value;
                        const itemView = viewHolder.itemView.value;

                        const customApp = config.apps.find(app => app.package === packageName);

                        iconView.setBackground.overload('android.graphics.drawable.Drawable')
                            .call(iconView, customDrawables[packageName][0]);

                        const languageIndex = getLanguageIndex();
                        textView.setText(StringClass.$new(customApp.name[languageIndex]));

                        let customClickAppListener = null;
                        if (clickAppListenerMap.hasOwnProperty(packageName)) {
                            customClickAppListener = clickAppListenerMap[packageName];
                        }
                        else {
                            customClickAppListener = CustomClickListener.$new();
                            clickAppListenerMap[packageName] = customClickAppListener;
                        }

                        itemView.setOnClickListener(customClickAppListener);
                    }
                } catch (e) {
                    console.log("[-] Ошибка в onBindViewHolder: " + e.message);
                    console.log(e.stack);
                }
            };

        console.log("[*] Frida: Хук на AllAppAdapter.onBindViewHolder установлен.");
    } catch (e) {
        console.log("[-] Ошибка при установке хука AllAppAdapter.onBindViewHolder: " + e.message);
    }
}

function updateThemeHook() {
    // --- Хук на NavigationBar (для замены иконок и обработки нажатий) ---
    try {
        // --- Хук на initScreenUpViews (для замены иконок и тегов при инициализации) ---
        NavigationBar.updateTheme.implementation = function () {
            console.log("[*] NavigationBar.updateTheme() вызван");

            // Сначала оригинальное поведение
            this.updateTheme.call(this);

            // Затем — наша замена
            patchNavigationIcons();
        };

    } catch (e) {

        console.log("[-] Ошибка при установке хуков NavigationBar: " + e.message);
    }
}

function init() {
    AppLauncher = Java.use("com.qinggan.launcher.base.utils.AppLauncher");
    AllAppAdapter = Java.use("com.qinggan.launcher.base.adapter.AllAppAdapter");
    StringClass = Java.use("java.lang.String");
    ActivityThread = Java.use('android.app.ActivityThread');
    BitmapDrawable = Java.use("android.graphics.drawable.BitmapDrawable");
    NavigationBar = Java.use("com.qinggan.mainlauncher.navigation.NavigationBar");
    R_id = Java.use("com.qinggan.mainlauncher.R$id");
    AllAppDataManager = Java.use("com.qinggan.launcher.base.allapp.AllAppDataManager");
    AppBean = Java.use("com.qinggan.launcher.base.bean.AppBean");
    PackageManager = ActivityThread.currentApplication().getPackageManager();
    AllAppBarView = Java.use("com.qinggan.launcher.base.allapp.AllAppBarView");

    const View$OnClickListener = Java.use('android.view.View$OnClickListener');

    CustomClickListener = Java.registerClass({
        name: 'com.qinggan.frida.CustomClickListener',
        implements: [View$OnClickListener],
        methods: {
            onClick: function (view) {
                try {
                    // Получаем AppBean из тега
                    const appBeanNative = view.getTag();
                    const appBean = Java.cast(appBeanNative, AppBean);
                    console.log("[+] Клик по: ");

                    if (appBean) {
                        const packageName = appBean.getPackageName();
                        console.log("[+] Клик по: " + packageName);

                        startApp(packageName);

                    }
                } catch (e) {
                    console.log("[-] Ошибка в кастомном клике: " + e.message);
                }
            }
        }
    });

    NavClickListener = Java.registerClass({
        name: 'com.qinggan.frida.NavClickListener',
        implements: [View$OnClickListener],
        methods: {
            onClick: function (view) {
                try {
                    const tagPkg = view.getTag(R_id.screen_up_item_package.value);
                    if (!tagPkg) return;

                    const packageName = tagPkg.toString();
                    startApp(packageName);
                } catch (e) {
                    console.log("[-] NavClickListener ошибка: " + e.message);
                }
            }
        }
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

    console.log("[+] Все хуки Frida успешно установлены (конфиг загружен при старте).");
}

Java.perform(() => { main(); });