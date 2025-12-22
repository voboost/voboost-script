import { Logger } from '../lib/logger.js';
import { LOG } from './keyboard-ru-log.js';

import {
    KEYBOARD_TEMPLATE_PATH,
    KEYBOARD_RU_CONFIG_PATH,
    loadConfig,
} from '../lib/utils.js';

const logger = new Logger('keyboard-ru-mod');

const KEYBOARD_CACHE_ID = 999999;
const EN_INPUT_METHOD_NAME = 'english_input_method';
const EN_INPUT_METHOD_WHITE_NAME = 'english_input_method_white';
const RU_INPUT_METHOD_NAME = 'russian_input_method';
const RU_INPUT_METHOD_WHITE_NAME = 'russian_input_method_white';

let InputModeSwitcher = null;
let SoftKey = null;
let SoftKeyToggle = null;
let SkbPool = null;
let SoftKeyboard = null;
let QingganIME = null;
let ActivityThread = null;
let KeyRow = null;
let R_drawable = null;
let R_xml = null;
let dravableIcons = null;

let SkbPoolInstance = null;
let InputModeSwitcherInstance = null;
let ThemeManager = null;

let template = null;
let currentLayout = null;
let needUpdateLyout = false;

let enModeLover = null;
let enModeUpper = null;
let enModeFirst = null;
let enModeHkb = null;
let enModeSymbol1 = null;
let enModeSymbol2 = null;

let WHITE_THEME = null;

let RUSSIAN_ICON = null;
let qwertyToJcuken = null;

const iconConfigNames = [
    EN_INPUT_METHOD_NAME,
    EN_INPUT_METHOD_WHITE_NAME,
    RU_INPUT_METHOD_NAME,
    RU_INPUT_METHOD_WHITE_NAME,
];

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

            const bytes = Base64.decode(iconData, Base64.DEFAULT.value);
            const iconBitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
            const iconDrawable = BitmapDrawable.$new(context.getResources(), iconBitmap);

            drawableMap[iconName] = iconDrawable;
        }
    } catch (e) {
        logger.error(`${LOG.ERROR_ICON_CONFIG} ${e.message}`);
        return null;
    }

    return drawableMap;
}

function createQwertyToJcuken(template) {
    const charMap = {};

    for (const row of template.keyboard.rows) {
        for (const key of row.keys) {
            if (key.code === undefined) continue;
            if (key.label == undefined) continue;

            const keyLabel = key.label;
            if (keyLabel === null) continue;
            if (keyLabel === '') continue;

            const keyCode = key.code;
            if (keyCode < 29) continue;
            if (keyCode > 54 && keyCode < 10001) continue;
            if (keyCode > 10007) continue;

            charMap[keyCode] = keyLabel;
        }
    }
    return charMap;
}

function resolveResId(resRef, context) {
    const resources = context.getResources();
    const pkgName = context.getPackageName();

    if (typeof resRef !== 'string' || !resRef.startsWith('@')) {
        return resRef;
    }

    try {
        // Parse "@type/name"
        const match = resRef.match(/^@(\w+)\/(.+)$/);
        if (!match) {
            logger.info(`${LOG.INVALID_RESOURCE_REF} ${resRef}`);
            return 0;
        }

        const [, type, name] = match;
        const id = resources.getIdentifier(name, type, pkgName);

        if (id === 0) {
            logger.info(`${LOG.RESOURCE_NOT_FOUND} ${resRef} (${type}/${name}) in package ${pkgName}`);
        }
        return id;
    } catch (e) {
        logger.error(`${LOG.ERROR_RESOLVING_RESOURCE} ${resRef}: ${e}`);
        return 0;
    }
}

function buildRussianKeyboard(xmlId, context, width, height, template) {
    const ThemeManagerInstance = ThemeManager.getInstance(context);
    const currentThemeTitle = ThemeManagerInstance.getCurrentThemeTitle();

    try {
        const attrs = template.keyboard.attrs;
        const rows = template.keyboard.rows;

        // Enable skb_template
        const skbTemplateResId = resolveResId(attrs.skb_template, context);
        const skbPool = SkbPool.getInstance();
        const skbTemplate = skbPool.getSkbTemplate(skbTemplateResId, context);

        if (!skbTemplate) {
            logger.error(
                `${LOG.SKB_TEMPLATE_NOT_FOUND} ${attrs.skb_template} (ID: ${skbTemplateResId})`
            );
            return null;
        }

        // Create a keyboard
        const softKeyboard = SoftKeyboard.$new(xmlId, skbTemplate, width, height);

        softKeyboard.setFlags(
            attrs.skb_cache_flag,
            attrs.skb_sticky_flag === undefined ? true : attrs.skb_sticky_flag,
            attrs.qwerty,
            attrs.qwerty_uppercase
        );
        softKeyboard.setKeyMargins(attrs.key_xmargin, attrs.key_ymargin);

        let currentX = 0.0;
        let currentY = 0.0;

        // Processing rows
        for (const row of rows) {
            const rowId = row.row_id === undefined ? -1 : row.row_id;
            currentX = row.start_pos_x === undefined ? 0.0 : row.start_pos_x;
            currentY = row.start_pos_y === undefined ? currentY : row.start_pos_y;

            softKeyboard.beginNewRow(rowId, currentY);

            // Process the keys in a row
            for (const keyJson of row.keys) {
                let softKey = null;
                const keyCode = keyJson.code === undefined ? 0 : keyJson.code;

                // 1. Key by ID (special)
                if (keyJson.id !== undefined) {
                    softKey = skbTemplate.getDefaultKey(keyJson.id);

                    if (!softKey) {
                        logger.info(`${LOG.GET_DEFAULT_KEY_NULL} ${keyJson.id}`);
                        continue;
                    }
                } else if (keyJson.toggle_states) {
                    // 2. Key with toggle states

                    softKey = SoftKeyToggle.$new();

                    // Create a linked list of states
                    let prevState = null;
                    let firstState = null;

                    for (const stateJson of keyJson.toggle_states) {
                        const state = softKey.createToggleState();

                        // Resolve state_id
                        const stateId = stateJson.state_id === undefined ? 0 : stateJson.state_id;
                        state.setStateId(stateId);

                        // Set the key code
                        state.mKeyCode.value = stateJson.code === undefined ? 0 : stateJson.code;

                        // Set the label
                        state.mKeyLabel.value =
                            stateJson.label === undefined ? null : stateJson.label;
                        let stateIcon = null;

                        if (WHITE_THEME === currentThemeTitle) {
                            // Enable icons
                            if (keyCode === 0) {
                                switch (stateId) {
                                    case 2:
                                        stateIcon = context.getDrawable(
                                            R_drawable.shift_lower_c53_white.value
                                        );
                                        break;
                                    case 3:
                                        stateIcon = context.getDrawable(
                                            R_drawable.shift_uppercase_c53_white.value
                                        );
                                        break;
                                    case 16:
                                        stateIcon = context.getDrawable(
                                            R_drawable.shift_uppercase_c53_temp_white.value
                                        );
                                        break;
                                }
                            } else if (keyCode === -2) {
                                if (stateId === 2 || stateId === 3 || stateId === 16) {
                                    if (
                                        Object.prototype.hasOwnProperty.call(
                                            dravableIcons,
                                            RU_INPUT_METHOD_WHITE_NAME
                                        )
                                    ) {
                                        stateIcon = dravableIcons[RU_INPUT_METHOD_WHITE_NAME];
                                    } else {
                                        stateIcon = context.getDrawable(
                                            R_drawable.english_input_method_white.value
                                        );
                                    }
                                }
                            }
                        } else {
                            if (keyCode === -2) {
                                if (stateId === 2 || stateId === 3 || stateId === 16) {
                                    if (
                                        Object.prototype.hasOwnProperty.call(
                                            dravableIcons,
                                            RU_INPUT_METHOD_NAME
                                        )
                                    ) {
                                        stateIcon = dravableIcons[RU_INPUT_METHOD_NAME];
                                    }
                                }
                            }
                        }

                        if (stateIcon !== null) {
                            state.mKeyIcon.value = stateIcon;
                        } else if (stateJson.icon) {
                            const iconId = resolveResId(stateJson.icon, context);
                            if (iconId) {
                                state.mKeyIcon.value = context.getDrawable(iconId);
                            }
                        }

                        if (stateJson.icon_popup) {
                            const iconPopupId = resolveResId(stateJson.icon_popup, context);
                            if (iconPopupId) {
                                state.mKeyIconPopup.value = context.getDrawable(iconPopupId);
                            }
                        }

                        // Set the key type if specified
                        if (stateJson.key_type !== undefined) {
                            const stateKeyType = skbTemplate.getKeyType(stateJson.key_type);
                            state.mKeyType.value = stateKeyType;
                        }

                        // Set flags
                        const stateRepeat =
                            stateJson.repeat !== undefined ? stateJson.repeat : attrs.repeat;
                        const stateBalloon =
                            stateJson.balloon !== undefined ? stateJson.balloon : attrs.balloon;

                        state.setStateFlags(stateRepeat, stateBalloon);

                        // Link the states
                        if (prevState) {
                            prevState.mNextState.value = state;
                        } else {
                            firstState = state;
                        }

                        prevState = state;
                    }

                    // Set the first state
                    if (firstState) {
                        softKey.setToggleStates(firstState);
                    }
                } else {
                    // 3. Regular key

                    softKey = SoftKey.$new();
                }

                const currentSoftKey = Java.cast(softKey, SoftKey);

                currentSoftKey.setKeyAttribute(
                    keyCode,
                    keyJson.label === undefined ? null : keyJson.label,
                    keyJson.repeat === undefined ? attrs.repeat : keyJson.repeat,
                    keyJson.balloon === undefined ? attrs.balloon : keyJson.balloon
                );

                // Set the ID of the popup keyboard
                if (keyJson.popup_skb) {
                    const popupSkbId = resolveResId(keyJson.popup_skb, context);
                    currentSoftKey.setPopupSkbId(popupSkbId);
                }

                // Set the key type
                const keyTypeId =
                    keyJson.key_type === undefined ? attrs.key_type || 0 : keyJson.key_type;
                const keyType = skbTemplate.getKeyType(keyTypeId);

                // Get icons for the key
                let keyIcon = null;
                let keyIconPopup = null;

                if (keyCode === -7 && WHITE_THEME === currentThemeTitle) {
                    keyIcon = context.getDrawable(R_drawable.hide_keyboard_white.value);
                }

                if (keyIcon === null && keyJson.icon) {
                    const iconId = resolveResId(keyJson.icon, context);

                    if (iconId) {
                        keyIcon = context.getDrawable(iconId);
                    }
                }

                if (keyJson.icon_popup) {
                    const iconPopupId = resolveResId(keyJson.icon_popup, context);

                    if (iconPopupId) {
                        keyIconPopup = context.getDrawable(iconPopupId);
                    }
                }

                if (keyIcon === null) {
                    keyIcon = skbTemplate.getDefaultKeyIcon(keyCode);
                }

                if (keyIconPopup === null) {
                    keyIconPopup = skbTemplate.getDefaultKeyIconPopup(keyCode);
                }

                currentSoftKey.setPopupSkbId(0);

                currentSoftKey.setKeyType(keyType, keyIcon, keyIconPopup);

                // Set the dimensions
                const keyWidth = keyJson.width == undefined ? attrs.width : keyJson.width;
                const keyHeight = attrs.height;

                const keyPositionX = currentX + keyWidth;
                const keyPositionY = currentY + keyHeight;

                // CHECKING the minimum size (as in the original)
                if (
                    keyPositionX - currentX < attrs.key_xmargin * 2.0 ||
                    keyPositionY - currentY < attrs.key_ymargin * 2.0
                ) {
                    logger.info(`${LOG.KEY_TOO_SMALL} ${keyJson.label || keyJson.id || 'unknown'}`);
                    continue;
                }

                currentSoftKey.setKeyDimensions(currentX, currentY, keyPositionX, keyPositionY);

                currentSoftKey.setSkbCoreSize(width, height);
                currentSoftKey.changeCase(false);

                currentX = keyPositionX;

                if (!softKeyboard.addSoftKey(currentSoftKey)) {
                    logger.error(`${LOG.FAILED_TO_ADD_KEY} ${keyJson.label || keyJson.id || 'unknown'}`);
                }
            }

            currentY += attrs.height;
        }

        const tooggleStateForCnCand = InputModeSwitcherInstance.getTooggleStateForCnCand();
        const toggleStates = InputModeSwitcherInstance.getToggleStates();

        softKeyboard.disableToggleState(tooggleStateForCnCand, false);
        softKeyboard.enableToggleStates(toggleStates);

        softKeyboard.setSkbCoreSize(width, height);

        return softKeyboard;
    } catch (e) {
        logger.error(`${LOG.KEYBOARD_BUILD_ERROR} ${e}`);
        return null;
    }
}

function getKeyboardFromCache() {
    const mSoftKeyboards = SkbPoolInstance.mSoftKeyboards.value;

    for (let i = 0; i < mSoftKeyboards.size(); i++) {
        const softKeyboard = Java.cast(mSoftKeyboards.elementAt(i), SoftKeyboard);

        if (softKeyboard.getCacheId() === KEYBOARD_CACHE_ID) {
            return softKeyboard;
        }
    }
    return null;
}

function switchSoftKeyMode(keyRows, isUpper) {
    for (let indexRow = 0; indexRow < keyRows.size(); indexRow++) {
        const row = Java.cast(keyRows.get(indexRow), KeyRow);

        for (let indexKey = 0; indexKey < row.mSoftKeys.value.size(); indexKey++) {
            let softKey = Java.cast(row.mSoftKeys.value.get(indexKey), SoftKey);

            let keyCode = softKey.getKeyCode();

            if (keyCode < 29) continue;
            if (keyCode > 54 && keyCode < 10001) continue;
            if (keyCode > 10007) continue;

            softKey.changeCase(isUpper);
        }
    }
}

function disableVoice() {
    const QGInputConfig = Java.use('com.qinggan.app.qgime.QGInputConfig');
    QGInputConfig.DISABLE_VOICE.value = true;
}

function resetCachedSkb() {
    SkbPoolInstance.resetCachedSkb();
}

function getKeyboardHook() {
    SkbPool.getSoftKeyboard.overload(
        'int',
        'int',
        'int',
        'int',
        'android.content.Context'
    ).implementation = function (cacheId, xmlId, width, height, context) {
        let softKeyboard = null;

        if (currentLayout !== 'ru') {
            softKeyboard = this.getSoftKeyboard
                .overload('int', 'int', 'int', 'int', 'android.content.Context')
                .call(this, cacheId, xmlId, width, height, context);
        } else {
            try {
                softKeyboard = getKeyboardFromCache();

                if (softKeyboard === null) {
                    softKeyboard = buildRussianKeyboard(xmlId, context, width, height, template);
                    softKeyboard.setCacheId(KEYBOARD_CACHE_ID);

                    this.mSoftKeyboards.value.add(softKeyboard);
                } else {
                    softKeyboard.setSkbCoreSize(width, height);
                    softKeyboard.setNewlyLoadedFlag(false);
                }

                // return softKeyboard;
            } catch (e) {
                logger.error(`${LOG.KEYBOARD_BUILD_ERROR} ${e}`);
                logger.error(e.stack);
            }
        }

        const tooggleStateForCnCand = InputModeSwitcherInstance.getTooggleStateForCnCand();
        const toggleStates = InputModeSwitcherInstance.getToggleStates();

        softKeyboard.disableToggleState(tooggleStateForCnCand, false);
        softKeyboard.enableToggleStates(toggleStates);

        return softKeyboard;
    };
}

function switchModeForUserKeyHook() {
    const QGToast = Java.use('com.pateo.material.dialog.QGToast');

    InputModeSwitcher.switchModeForUserKey.implementation = function (i, z) {
        const oldLayout = currentLayout;

        if (i === -2) {
            // Language switch key
            if (
                this.mInputMode.value === enModeSymbol1 ||
                this.mInputMode.value === enModeSymbol2
            ) {
                currentLayout = 'en';
                needUpdateLyout = oldLayout !== currentLayout;
                return this.switchModeForUserKey.call(this, i, z);
            }

            currentLayout = currentLayout === 'en' ? 'ru' : 'en';
            const newIcon = currentLayout === 'ru' ? RUSSIAN_ICON : R_drawable.ime_en.value;

            this.mInputIcon.value = newIcon;
            needUpdateLyout = oldLayout !== currentLayout;

            return newIcon;
        } else if (i == -3) {
            currentLayout = 'en';
        } else if (i === -10) {
            const message =
                currentLayout === 'ru'
                    ? 'Голосовой ввод недоступен для русского языка.'
                    : 'Voice input is not available for English.';

            QGToast.makeText
                .overload('android.content.Context', 'java.lang.CharSequence', 'int')
                .call(QGToast, this.mImeService.value, message, 2)
                .show();

            return this.mInputIcon.value;
        }

        needUpdateLyout = oldLayout !== currentLayout;
        return this.switchModeForUserKey.call(this, i, z);
    };
}

function updateInputModeHook() {
    const SkbContainer = Java.use('com.qinggan.app.qgime.SkbContainer');

    SkbContainer.updateInputMode.implementation = function () {
        this.updateInputMode.call(this);

        if (needUpdateLyout) {
            this.updateSkbLayout();
            needUpdateLyout = false;
        }
    };
}

function saveInputModeHook() {
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

function processKeyHook() {
    const EnglishInputProcessor = Java.use('com.qinggan.app.qgime.EnglishInputProcessor');

    EnglishInputProcessor.processKey.implementation = function (ic, event, isShift, commit) {
        if (currentLayout !== 'ru') {
            return this.processKey.call(this, ic, event, isShift, commit);
        }

        const keyCode = event.getKeyCode();
        if (!Object.prototype.hasOwnProperty.call(qwertyToJcuken, keyCode)) {
            return this.processKey.call(this, ic, event, isShift, commit);
        }

        const keyLabel = qwertyToJcuken[keyCode];
        const keyChar = isShift ? keyLabel.toUpperCase() : keyLabel.toLowerCase();

        if (commit) {
            ic.commitText(Java.use('java.lang.String').$new(keyChar), 1);
        }

        this.mLastKeyCode.value = keyCode;
        return true;
    };
}

function responseSoftKeyEventHook() {
    QingganIME.responseSoftKeyEvent.implementation = function (softKey) {
        this.responseSoftKeyEvent.call(this, softKey);

        if (needUpdateLyout) {
            this.mSkbContainer.value.updateInputMode();
            return;
        }

        if (currentLayout === 'ru') {
            let keyCode = softKey.getKeyCode();
            if (!this.mInputModeSwitcher.value.isQwertyFirstMode()) return;

            if (keyCode > 10000 && keyCode < 10008) {
                this.mInputModeSwitcher.value.switchModeForUserKey(-1, true);
                this.resetToIdleState(false);
                this.mSkbContainer.value.updateInputMode();
                return;
            }
        }
    };
}

function switchQwertyModeHook() {
    SoftKeyboard.switchQwertyMode.implementation = function (i, isUpper) {
        this.switchQwertyMode.call(this, i, isUpper);

        if (currentLayout !== 'ru') return;

        const keyRows = this.mKeyRows.value;

        switchSoftKeyMode(keyRows, isUpper);
    };
}

function enableToggleStatesHook() {
    SoftKeyboard.enableToggleStates.implementation = function (toggleStates) {
        this.enableToggleStates.call(this, toggleStates);

        if (currentLayout !== 'ru') return;

        const isUpper = this.mIsQwertyUpperCase.value;
        const keyRows = this.mKeyRows.value;

        switchSoftKeyMode(keyRows, isUpper);
    };
}

function loadKeyboardHook() {
    const XmlKeyboardLoader = Java.use('com.qinggan.app.qgime.XmlKeyboardLoader');
    const ToggleState = Java.use('com.qinggan.app.qgime.SoftKeyToggle$ToggleState');
    const List = Java.use('java.util.List');

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

        if (xmlId != R_xml.skb_qwerty.value && xmlId != R_xml.skb_qwerty_no_voice.value) {
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

function getKeyLabelHook() {
    SoftKeyToggle.getKeyLabel.implementation = function () {
        if (currentLayout !== 'ru') return this.getKeyLabel.call(this);
        if (this.mKeyCode.value !== 66) return this.getKeyLabel.call(this);

        const toggleState = this.getToggleState();
        if (toggleState === null) return this.getKeyLabel.call(this);

        return toggleState.mKeyLabel.value;
    };
}

function init() {
    InputModeSwitcher = Java.use('com.qinggan.app.qgime.InputModeSwitcher');
    SoftKey = Java.use('com.qinggan.app.qgime.SoftKey');
    SoftKeyToggle = Java.use('com.qinggan.app.qgime.SoftKeyToggle');
    SkbPool = Java.use('com.qinggan.app.qgime.SkbPool');
    SoftKeyboard = Java.use('com.qinggan.app.qgime.SoftKeyboard');
    QingganIME = Java.use('com.qinggan.app.qgime.QingganIME');
    ThemeManager = Java.use('com.qinggan.theme.ThemeManager');
    ActivityThread = Java.use('android.app.ActivityThread');
    KeyRow = Java.use('com.qinggan.app.qgime.SoftKeyboard$KeyRow');

    R_drawable = Java.use('com.qinggan.app.qgime.R$drawable');
    R_xml = Java.use('com.qinggan.app.qgime.R$xml');

    SkbPoolInstance = SkbPool.getInstance();
    InputModeSwitcherInstance = InputModeSwitcher.getInstance();

    enModeLover = InputModeSwitcher.MODE_SKB_ENGLISH_LOWER.value;
    enModeUpper = InputModeSwitcher.MODE_SKB_ENGLISH_UPPER.value;
    enModeFirst = InputModeSwitcher.MODE_SKB_ENGLISH_FIRST.value;
    enModeHkb = InputModeSwitcher.MODE_HKB_ENGLISH.value;
    enModeSymbol1 = InputModeSwitcher.MODE_SKB_SYMBOL1_EN.value; //33685504
    enModeSymbol2 = InputModeSwitcher.MODE_SKB_SYMBOL2_EN.value; //33685504

    WHITE_THEME = ThemeManager.DEFAULT_THEME_TITLE2.value;

    RUSSIAN_ICON = R_drawable.ime_pinyin.value;

    // Load template config with full parameter support
    // Priority: 1) params.config, 2) params.configPath, 3) KEYBOARD_TEMPLATE_PATH
    template = loadConfig(KEYBOARD_TEMPLATE_PATH, logger);

    // Config is required for this agent
    if (!template) {
        logger.error(LOG.CONFIG_NOT_AVAILABLE);
        return;
    }

    qwertyToJcuken = createQwertyToJcuken(template);

    // Load keyboard config with full parameter support
    // Priority: 1) params.config, 2) params.configPath, 3) KEYBOARD_RU_CONFIG_PATH
    const keyboardConfig = loadConfig(KEYBOARD_RU_CONFIG_PATH, logger);

    if (keyboardConfig) {
        dravableIcons = createDrawableIons(JSON.stringify(keyboardConfig));
    }

    currentLayout = 'en';
}

function main() {
    init();

    // Config validation already done in init()
    getKeyboardHook();
    switchModeForUserKeyHook();
    saveInputModeHook();
    responseSoftKeyEventHook();
    updateInputModeHook();
    processKeyHook();
    switchQwertyModeHook();
    enableToggleStatesHook();
    loadKeyboardHook();
    getKeyLabelHook();

    disableVoice();
    resetCachedSkb();

    logger.info(LOG.HOOKS_INSTALLED);
}

Java.perform(function () {
    main();
});
