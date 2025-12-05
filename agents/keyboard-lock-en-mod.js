import {
    KEYBOARD_LOCK_EN_CONFIG_PATH,
    LoadTextFile,
} from "./utils.js";

let ActivityThread = null;
let dravableIcons = null;

const EN_INPUT_METHOD_NAME = "english_input_method";
const EN_INPUT_METHOD_WHITE_NAME = "english_input_method_white";

const iconConfigNames = [EN_INPUT_METHOD_NAME, EN_INPUT_METHOD_WHITE_NAME];

function createDrawableIons(configContent) {

    const Base64 = Java.use("android.util.Base64");
    const BitmapFactory = Java.use("android.graphics.BitmapFactory");
    const BitmapDrawable = Java.use("android.graphics.drawable.BitmapDrawable");
    const context = ActivityThread.currentApplication().getApplicationContext();

    const drawableMap = {};
    try {
        const config = JSON.parse(configContent);
        const drawable = config.drawable;

        for (let iconName of iconConfigNames) {

            if (!Object.prototype.hasOwnProperty.call(drawable, iconName)) continue;

            const iconData = drawable[iconName];

            if (iconData === "") continue;

            const bytes = Base64.decode(iconData, Base64.DEFAULT.value);
            const iconBitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
            const iconDrawable = BitmapDrawable.$new(context.getResources(), iconBitmap);

            drawableMap[iconName] = iconDrawable;
        }
    } catch (e) {
        console.error("[-] Error loading icon config:", e.message);
        return null;
    }

    return drawableMap;
}

function disableVoice() {

    const QGInputConfig = Java.use("com.qinggan.app.qgime.QGInputConfig");
    QGInputConfig.DISABLE_VOICE.value = true;

    console.log(`voice disable: ${QGInputConfig.DISABLE_VOICE.value}`);
}

function resetCachedSkb() {

    const SkbPool = Java.use("com.qinggan.app.qgime.SkbPool");
    const SkbPoolInstance = SkbPool.getInstance();

    SkbPoolInstance.resetCachedSkb();
}

function saveInputModeHook() {

    const InputModeSwitcher = Java.use("com.qinggan.app.qgime.InputModeSwitcher");

    const enModeLover = InputModeSwitcher.MODE_SKB_ENGLISH_LOWER.value;
    const enModeUpper = InputModeSwitcher.MODE_SKB_ENGLISH_UPPER.value;
    const enModeFirst = InputModeSwitcher.MODE_SKB_ENGLISH_FIRST.value;
    const enModeHkb = InputModeSwitcher.MODE_HKB_ENGLISH.value;
    const enModeSymbol1 = InputModeSwitcher.MODE_SKB_SYMBOL1_EN.value;
    const enModeSymbol2 = InputModeSwitcher.MODE_SKB_SYMBOL2_EN.value;

    InputModeSwitcher.saveInputMode.implementation = function (mode) {

        if (mode !== enModeLover &&
            mode !== enModeUpper &&
            mode !== enModeFirst &&
            mode !== enModeHkb &&
            mode !== enModeSymbol1 &&
            mode !== enModeSymbol2) {

            mode = enModeFirst;
        }

        return this.saveInputMode.call(this, mode);
    };
}

function loadKeyboardHook() {

    const XmlKeyboardLoader = Java.use("com.qinggan.app.qgime.XmlKeyboardLoader");
    const ToggleState = Java.use("com.qinggan.app.qgime.SoftKeyToggle$ToggleState");
    const KeyRow = Java.use("com.qinggan.app.qgime.SoftKeyboard$KeyRow");
    const ThemeManager = Java.use("com.qinggan.theme.ThemeManager");
    const SoftKeyboard = Java.use("com.qinggan.app.qgime.SoftKeyboard");
    const R_xml = Java.use("com.qinggan.app.qgime.R$xml");
    const SoftKeyToggle = Java.use("com.qinggan.app.qgime.SoftKeyToggle");
    const List = Java.use("java.util.List");

    const WHITE_THEME = ThemeManager.DEFAULT_THEME_TITLE2.value;

    const context = ActivityThread.currentApplication().getApplicationContext();

    const ThemeManagerInstance = ThemeManager.getInstance(context);
    const currentThemeTitle = ThemeManagerInstance.getCurrentThemeTitle();

    var keyRowsField = SoftKeyboard.class.getDeclaredField("mKeyRows");
    keyRowsField.setAccessible(true);

    var softKeysField = KeyRow.class.getDeclaredField("mSoftKeys");
    softKeysField.setAccessible(true);

    var toggleStateField = SoftKeyToggle.class.getDeclaredField("mToggleState");
    toggleStateField.setAccessible(true);

    const mKeyIconField = ToggleState.class.getDeclaredField("mKeyIcon");
    mKeyIconField.setAccessible(true);

    const mNextStateField = ToggleState.class.getDeclaredField("mNextState");
    mNextStateField.setAccessible(true);

    XmlKeyboardLoader.loadKeyboard.implementation = function (xmlId, width, height) {

        const softKeyboard = this.loadKeyboard.call(this, xmlId, width, height);

        if (xmlId != R_xml.skb_qwerty.value &&
            xmlId != R_xml.skb_qwerty_no_voice.value) {

            return softKeyboard;
        }

        const keyRows = Java.cast(keyRowsField.get(softKeyboard), List);

        for (let rowIndex = 0; rowIndex < keyRows.size(); rowIndex++) {

            const keyRow = keyRows.get(rowIndex);
            const softKeys = Java.cast(softKeysField.get(keyRow), List);

            for (let keyIndex = 0; keyIndex < softKeys.size(); keyIndex++) {

                const softKey = softKeys.get(keyIndex);

                const softKeyClassName = softKey.getClass().getName();

                if (softKeyClassName !== "com.qinggan.app.qgime.SoftKeyToggle") continue;

                const softKeyToggle = Java.cast(softKey, SoftKeyToggle);

                if (softKeyToggle.getKeyCode() != -2) continue;

                let toggleState = Java.cast(toggleStateField.get(softKeyToggle), ToggleState);

                let keyIcon = null;

                if (WHITE_THEME === currentThemeTitle) {

                    if (Object.prototype.hasOwnProperty.call(dravableIcons, EN_INPUT_METHOD_WHITE_NAME)) {

                        keyIcon = dravableIcons[EN_INPUT_METHOD_WHITE_NAME];
                    }

                } else {

                    if (Object.prototype.hasOwnProperty.call(dravableIcons, EN_INPUT_METHOD_NAME)) {

                        keyIcon = dravableIcons[EN_INPUT_METHOD_NAME];
                    }
                }

                if (!keyIcon) continue;

                while (toggleState !== null) {
                    mKeyIconField.set(toggleState, keyIcon);
                    const nextState = mNextStateField.get(toggleState);

                    if (nextState === null) break;

                    toggleState = Java.cast(nextState, ToggleState);
                }
            }
        }

        return softKeyboard;
    };
}

function init() {

    ActivityThread = Java.use("android.app.ActivityThread");

    const configContent = LoadTextFile(KEYBOARD_LOCK_EN_CONFIG_PATH);
    dravableIcons = createDrawableIons(configContent);
}

function main() {

    init();

    saveInputModeHook();
    loadKeyboardHook();

    disableVoice();
    resetCachedSkb();
}

Java.perform(function () { main(); });
