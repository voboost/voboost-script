const LANGUAGE_CONFIG_PATH = "/data/local/tmp/test/language_config.json";
const APP_VIEWPORT_CONFIG_PATH = "/data/local/tmp/test/apps_viewport_config.json";
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

let SystemProperties = null;
let Rect = null;
let ActivityRecord = null;
let Locale = null;
let WindowManagerService = null;

let config = null;
let currentLocale = null;

// 2. Константы для отступов
const PADDING_VALUES = {
    "left": 145,
    "up": 45,
    "none": 0
};

// 3. Функция получения текущего состояния экрана
function getScreenLiftState() {
    return SystemProperties.get('persist.qg.canbus.bcm_screenAutoLiftFdb') || "2";
}

function createLocale(languageConfig) {
    if (languageConfig.language === "RU") return Locale.$new("ru", "RU");
    if (languageConfig.language === "EU") return Locale.$new("en", "US");
    return Locale.$new("en", "US");
}

// 4. Основная функция применения настроек к приложению
function applyAppSettings(activityRecord, displayId) {
    try {
        const packageName = activityRecord.packageName.value;
        const currentDisplay = displayId === 0 ? "main" : "second";
        const screenLift = getScreenLiftState();

        // Поиск настроек для приложения
        const appConfig = config.apps.find(app => app.package === packageName);
        if (!appConfig) return; // Пропускаем приложения не из конфига

        // Проверка разрешенных экранов
        if (!appConfig.screen.includes(currentDisplay)) return;

        // Вычисление границ с учетом состояния экрана
        let left = 0, top = 0, right = 1920, bottom = 1080;

        // Применение отступов из конфига
        if (appConfig.padding.includes("left")) left = PADDING_VALUES.left;
        if (appConfig.padding.includes("up")) top = PADDING_VALUES.up;

        // Корректировка высоты в зависимости от состояния экрана
        if (screenLift === "1") {
            bottom = 530; // Экран опущен
        } else if (screenLift === "2") {
            bottom = 720; // Экран поднят
        }

        // Создание и применение новых границ
        const newBounds = Rect.$new(left, top, right, bottom);
        activityRecord.mSizeCompatBounds.value = newBounds;

        // Применение масштаба
        activityRecord.mSizeCompatScale.value = appConfig.scale;

        // Применение DPI и ориентации
        const configAR = activityRecord.getConfiguration();
        configAR.densityDpi.value = appConfig.dpi;
        configAR.orientation.value = 2; // Landscape всегда
        configAR.locale.value = currentLocale;
        configAR.setLocale(currentLocale);
        activityRecord.onConfigurationChanged(configAR);

        console.log(`✅ Applied settings to ${packageName} on ${currentDisplay}, screen state: ${screenLift}`);
    } catch (e) {
        console.log(`❌ Error applying settings: ${e.message}`);
        console.log(e.stack);
    }
}

function onDisplayChangedHook() {

    ActivityRecord.onDisplayChanged.overload("com.android.server.wm.DisplayContent")
        .implementation = function (displayContent) {
            try {
                // Вызов оригинального метода
                this.onDisplayChanged.call(this, displayContent);

                const displayId = displayContent.getDisplayId();
                applyAppSettings(this, displayId);
            }
            catch (e) {
                console.error('[launcher_navbar_mod] Error in hook:', e.message);
                console.error(e.stack);
            }
        };
}

function init() {

    SystemProperties = Java.use('android.os.SystemProperties');
    Rect = Java.use('android.graphics.Rect');
    ActivityRecord = Java.use("com.android.server.wm.ActivityRecord");
    WindowManagerService = Java.use("com.android.server.wm.WindowManagerService");
    Locale = Java.use("java.util.Locale");
}

function main() {
    init();

    const appViewPortContent = LoadTextFile(APP_VIEWPORT_CONFIG_PATH);
    config = parseConfig(appViewPortContent);

    const languageContent = LoadTextFile(LANGUAGE_CONFIG_PATH);
    const languageConfig = parseConfig(languageContent);
    currentLocale = createLocale(languageConfig);

    onDisplayChangedHook();
}

Java.perform(function () { main() });