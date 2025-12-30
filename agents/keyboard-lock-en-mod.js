import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './keyboard-lock-en-log.js';

import {
    KEYBOARD_LOCK_EN_CONFIG_PATH,
    setFieldValue,
    getFieldValue,
    loadConfig,
    runAgent,
} from '../lib/utils.js';

const logger = new Logger('keyboard-lock-en-mod');

let ActivityThread = null;
let dravableIcons = null;

const EN_INPUT_METHOD_NAME = 'english_input_method';
const EN_INPUT_METHOD_WHITE_NAME = 'english_input_method_white';

const iconConfigNames = [EN_INPUT_METHOD_NAME, EN_INPUT_METHOD_WHITE_NAME];

function createDrawableIons(configContent) {
    const Base64 = Java.use('android.util.Base64');
    const BitmapFactory = Java.use('android.graphics.BitmapFactory');
    const BitmapDrawable = Java.use('android.graphics.drawable.BitmapDrawable');
    const context = ActivityThread.currentApplication().getApplicationContext();

    const drawableMap = {};
    try {
        const config = JSON.parse(configContent);
        const drawable = config.drawable;

        for (let iconName of iconConfigNames) {
            if (!Object.prototype.hasOwnProperty.call(drawable, iconName)) continue;

            const iconData = drawable[iconName];

            if (iconData === '') continue;

            const bytes = Base64.decode(iconData, getFieldValue(Base64, 'DEFAULT'));
            const iconBitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
            const iconDrawable = BitmapDrawable.$new(context.getResources(), iconBitmap);

            drawableMap[iconName] = iconDrawable;
        }
    } catch (e) {
        logger.error(`${ERROR.ICON_CONFIG} ${e.message}`);
        return null;
    }

    return drawableMap;
}

function disableVoice() {
    const QGInputConfig = Java.use('com.qinggan.app.qgime.QGInputConfig');

    // QGInputConfig.DISABLE_VOICE.value = true;
    setFieldValue(QGInputConfig, 'DISABLE_VOICE', true);

    logger.debug(`${DEBUG.VOICE_DISABLED} ${getFieldValue(QGInputConfig, 'DISABLE_VOICE')}`);
}

function resetCachedSkb() {
    const SkbPool = Java.use('com.qinggan.app.qgime.SkbPool');
    const SkbPoolInstance = SkbPool.getInstance();

    SkbPoolInstance.resetCachedSkb();
}

function saveInputModeHook() {
    const InputModeSwitcher = Java.use('com.qinggan.app.qgime.InputModeSwitcher');

    const enModeLover = getFieldValue(InputModeSwitcher, 'MODE_SKB_ENGLISH_LOWER');
    const enModeUpper = getFieldValue(InputModeSwitcher, 'MODE_SKB_ENGLISH_UPPER');
    const enModeFirst = getFieldValue(InputModeSwitcher, 'MODE_SKB_ENGLISH_FIRST');
    const enModeHkb = getFieldValue(InputModeSwitcher, 'MODE_HKB_ENGLISH');
    const enModeSymbol1 = getFieldValue(InputModeSwitcher, 'MODE_SKB_SYMBOL1_EN');
    const enModeSymbol2 = getFieldValue(InputModeSwitcher, 'MODE_SKB_SYMBOL2_EN');

    InputModeSwitcher.saveInputMode.implementation = function (mode) {
        if (
            mode !== enModeLover &&
            mode !== enModeUpper &&
            mode !== enModeFirst &&
            mode !== enModeHkb &&
            mode !== enModeSymbol1 &&
            mode !== enModeSymbol2
        ) {
            mode = enModeFirst;
        }

        return this.saveInputMode.call(this, mode);
    };
}

function loadKeyboardHook() {
    const XmlKeyboardLoader = Java.use('com.qinggan.app.qgime.XmlKeyboardLoader');
    const ToggleState = Java.use('com.qinggan.app.qgime.SoftKeyToggle$ToggleState');
    const KeyRow = Java.use('com.qinggan.app.qgime.SoftKeyboard$KeyRow');
    const ThemeManager = Java.use('com.qinggan.theme.ThemeManager');
    const SoftKeyboard = Java.use('com.qinggan.app.qgime.SoftKeyboard');
    const R_xml = Java.use('com.qinggan.app.qgime.R$xml');
    const SoftKeyToggle = Java.use('com.qinggan.app.qgime.SoftKeyToggle');
    const List = Java.use('java.util.List');

    const WHITE_THEME = getFieldValue(ThemeManager, 'DEFAULT_THEME_TITLE2');

    const context = ActivityThread.currentApplication().getApplicationContext();

    const ThemeManagerInstance = ThemeManager.getInstance(context);
    const currentThemeTitle = ThemeManagerInstance.getCurrentThemeTitle();

    var keyRowsField = SoftKeyboard.class.getDeclaredField('mKeyRows');
    keyRowsField.setAccessible(true);

    var softKeysField = KeyRow.class.getDeclaredField('mSoftKeys');
    softKeysField.setAccessible(true);

    var toggleStateField = SoftKeyToggle.class.getDeclaredField('mToggleState');
    toggleStateField.setAccessible(true);

    const mKeyIconField = ToggleState.class.getDeclaredField('mKeyIcon');
    mKeyIconField.setAccessible(true);

    const mNextStateField = ToggleState.class.getDeclaredField('mNextState');
    mNextStateField.setAccessible(true);

    XmlKeyboardLoader.loadKeyboard.implementation = function (xmlId, width, height) {
        const softKeyboard = this.loadKeyboard.call(this, xmlId, width, height);

        if (
            xmlId != getFieldValue(R_xml, 'skb_qwerty') &&
            xmlId != getFieldValue(R_xml, 'skb_qwerty_no_voice')
        ) {
            return softKeyboard;
        }

        const keyRows = Java.cast(keyRowsField.get(softKeyboard), List);

        for (let rowIndex = 0; rowIndex < keyRows.size(); rowIndex++) {
            const keyRow = keyRows.get(rowIndex);
            const softKeys = Java.cast(softKeysField.get(keyRow), List);

            for (let keyIndex = 0; keyIndex < softKeys.size(); keyIndex++) {
                const softKey = softKeys.get(keyIndex);

                const softKeyClassName = softKey.getClass().getName();

                if (softKeyClassName !== 'com.qinggan.app.qgime.SoftKeyToggle') continue;

                const softKeyToggle = Java.cast(softKey, SoftKeyToggle);

                if (softKeyToggle.getKeyCode() != -2) continue;

                let toggleState = Java.cast(toggleStateField.get(softKeyToggle), ToggleState);

                let keyIcon = null;

                if (WHITE_THEME === currentThemeTitle) {
                    if (
                        Object.prototype.hasOwnProperty.call(
                            dravableIcons,
                            EN_INPUT_METHOD_WHITE_NAME
                        )
                    ) {
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
    ActivityThread = Java.use('android.app.ActivityThread');

    const config = loadConfig(KEYBOARD_LOCK_EN_CONFIG_PATH, logger);

    if (config) {
        dravableIcons = createDrawableIons(JSON.stringify(config));
    }
}

function main() {
    logger.info(INFO.STARTING);

    init();
    saveInputModeHook();

    try {
        loadKeyboardHook();
    } catch (e) {
        logger.error('loadKeyboardHook failed: ' + e.message);
    }

    disableVoice();
    resetCachedSkb();

    logger.info(INFO.STARTED);
}

runAgent(main);
