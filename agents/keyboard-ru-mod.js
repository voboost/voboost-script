/**
 * Russian Keyboard Layout Modification Agent
 *
 * This Frida agent modifies the Qinggan IME keyboard to support Russian (JCUKEN) layout
 * alongside the default English (QWERTY) layout. It intercepts keyboard rendering and
 * input processing to enable seamless switching between English and Russian layouts.
 *
 * Features:
 * - Dynamic keyboard layout switching (EN ↔ RU)
 * - QWERTY to JCUKEN character mapping
 * - Custom keyboard icons for language indicators
 * - Theme-aware icon rendering (white/dark themes)
 * - Voice input disabled for Russian layout
 *
 * @module keyboard-ru-mod
 */

import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './keyboard-ru-log.js';

import {
    KEYBOARD_TEMPLATE_PATH,
    KEYBOARD_RU_CONFIG_PATH,
    setFieldValue,
    getFieldValue,
    loadConfig,
    runAgent,
} from '../lib/utils.js';

const logger = new Logger('keyboard-ru-mod');

// Manifest metadata consumed by the manifest generator. `process` is the
// Android process the daemon injects this agent into (hooks classes in
// `com.qinggan.app.qgime`); `boot:false` = inject as soon as the target is
// reachable.
export const AGENT_META = {
    id: 'keyboard-ru',
    process: 'com.qinggan.app.qgime',
    boot: false,
};

// Keyboard cache identifier
const KEYBOARD_CACHE_ID = 999999;

// Icon configuration names
const EN_INPUT_METHOD_NAME = 'english_input_method';
const EN_INPUT_METHOD_WHITE_NAME = 'english_input_method_white';
const RU_INPUT_METHOD_NAME = 'russian_input_method';
const RU_INPUT_METHOD_WHITE_NAME = 'russian_input_method_white';

// Key code boundaries for character keys
const KEY_CODE_MIN_LETTER = 29;
const KEY_CODE_MAX_LETTER = 54;
const KEY_CODE_MIN_RUSSIAN = 10001;
const KEY_CODE_MAX_RUSSIAN = 10007;

// Special key codes
const KEY_CODE_LANGUAGE_SWITCH = -2;
const KEY_CODE_SYMBOL_SWITCH = -3;
const KEY_CODE_VOICE_INPUT = -10;
const KEY_CODE_HIDE_KEYBOARD = -7;
const KEY_CODE_ENTER = 66;

// Toggle state IDs for shift key
const TOGGLE_STATE_LOWER = 2;
const TOGGLE_STATE_UPPER = 3;
const TOGGLE_STATE_TEMP_UPPER = 16;

// Java class references
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
let drawableIcons = null;

// Instance references
let SkbPoolInstance = null;
let InputModeSwitcherInstance = null;
let ThemeManager = null;

// Configuration and state
let template = null;
let currentLayout = null;
let needUpdateLayout = false;

// Input mode references
let enModeLower = null;
let enModeUpper = null;
let enModeFirst = null;
let enModeHkb = null;
let enModeSymbol1 = null;
let enModeSymbol2 = null;

// Theme constants
let WHITE_THEME = null;

// Icon references
let RUSSIAN_ICON = null;
let qwertyToJcuken = null;

const iconConfigNames = [
    EN_INPUT_METHOD_NAME,
    EN_INPUT_METHOD_WHITE_NAME,
    RU_INPUT_METHOD_NAME,
    RU_INPUT_METHOD_WHITE_NAME,
];

/**
 * Creates drawable icons from base64-encoded configuration.
 *
 * Parses the keyboard configuration JSON and converts base64-encoded icon data
 * into Android Drawable objects for use in the keyboard UI.
 *
 * @param {string} configContent - JSON string containing icon configuration with base64 data
 * @returns {Object|null} Map of icon names to BitmapDrawable objects, or null on error
 *
 * @example
 * const config = '{"drawable": {"english_input_method": "base64data..."}}';
 * const icons = createDrawableIcons(config);
 * // Returns: { english_input_method: BitmapDrawable, ... }
 */
function createDrawableIcons(configContent) {
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

/**
 * Creates a mapping from QWERTY key codes to JCUKEN (Russian) characters.
 *
 * Parses the keyboard template configuration and builds a character map that
 * translates English QWERTY key positions to their Russian JCUKEN equivalents.
 * Only processes letter keys within the valid key code ranges.
 *
 * @param {Object} template - Keyboard template configuration object
 * @param {Object} template.keyboard - Keyboard layout definition
 * @param {Array<Object>} template.keyboard.rows - Array of keyboard rows
 * @returns {Object} Map of key codes to Russian characters
 *
 * @example
 * const template = { keyboard: { rows: [...] } };
 * const mapping = createQwertyToJcuken(template);
 * // Returns: { 29: 'й', 30: 'ц', 31: 'у', ... }
 */
function createQwertyToJcuken(template) {
    const charMap = {};

    for (const row of template.keyboard.rows) {
        for (const key of row.keys) {
            if (key.code === undefined) continue;
            if (key.label == undefined) continue;

            const keyLabel = key.label;
            if (keyLabel === '') continue;

            const keyCode = key.code;
            // Filter valid letter key codes
            if (keyCode < KEY_CODE_MIN_LETTER) continue;
            if (keyCode > KEY_CODE_MAX_LETTER && keyCode < KEY_CODE_MIN_RUSSIAN) continue;
            if (keyCode > KEY_CODE_MAX_RUSSIAN) continue;

            charMap[keyCode] = keyLabel;
        }
    }
    return charMap;
}

/**
 * Resolves a character from the QWERTY to JCUKEN mapping.
 *
 * @param {number} keyCode - The key code to resolve
 * @param {Object} mapping - The character mapping object
 * @returns {string|null} The mapped character or null if not found
 *
 * @example
 * const mapping = { 29: 'й', 30: 'ц' };
 * resolveKeyChar(29, mapping); // Returns: 'й'
 * resolveKeyChar(999, mapping); // Returns: null
 */
function resolveKeyChar(keyCode, mapping) {
    if (!mapping || typeof mapping !== 'object') return null;
    if (typeof keyCode !== 'number') return null;

    return Object.prototype.hasOwnProperty.call(mapping, keyCode) ? mapping[keyCode] : null;
}

/**
 * Checks if the given key code falls within the Russian key code range.
 *
 * @param {number} keyCode - The key code to check
 * @returns {boolean} True if the key code is within the Russian key code range
 *
 * @example
 * isRussianKeyCode(10001); // Returns: true
 * isRussianKeyCode(10007); // Returns: true
 * isRussianKeyCode(29); // Returns: false
 */
function isRussianKeyCode(keyCode) {
    if (typeof keyCode !== 'number') return false;
    return keyCode >= KEY_CODE_MIN_RUSSIAN && keyCode <= KEY_CODE_MAX_RUSSIAN;
}

/**
 * Resolves Android resource references to resource IDs.
 *
 * Converts resource reference strings (e.g., "@drawable/icon_name") into
 * numeric resource IDs that can be used to load resources from the Android system.
 *
 * @param {string|number} resRef - Resource reference string or numeric ID
 * @param {Object} context - Android Context object
 * @returns {number} Resource ID, or 0 if resolution fails
 *
 * @example
 * resolveResId("@drawable/icon_name", context); // Returns: 2130837504
 * resolveResId(12345, context); // Returns: 12345 (passthrough)
 */
function resolveResId(resRef, context) {
    const resources = context.getResources();
    const pkgName = context.getPackageName();

    if (typeof resRef !== 'string' || !resRef.startsWith('@')) {
        return resRef;
    }

    try {
        // Parse "@type/name" format
        const match = resRef.match(/^@(\w+)\/(.+)$/);
        if (!match) {
            logger.debug(`${DEBUG.INVALID_RESOURCE_REF} ${resRef}`);
            return 0;
        }

        const [, type, name] = match;
        const id = resources.getIdentifier(name, type, pkgName);

        if (id === 0) {
            logger.debug(
                `${DEBUG.RESOURCE_NOT_FOUND} ${resRef} (${type}/${name}) in package ${pkgName}`
            );
        }
        return id;
    } catch (e) {
        logger.error(`${ERROR.RESOLVING_RESOURCE} ${resRef}: ${e}`);
        return 0;
    }
}

/**
 * Builds a Russian keyboard layout from template configuration.
 *
 * Constructs a complete SoftKeyboard object with Russian JCUKEN layout based on
 * the provided template. Handles key creation, icon assignment, toggle states,
 * and theme-specific rendering.
 *
 * @param {number} xmlId - XML resource ID for the keyboard layout
 * @param {Object} context - Android Context object
 * @param {number} width - Keyboard width in pixels
 * @param {number} height - Keyboard height in pixels
 * @param {Object} template - Keyboard template configuration
 * @returns {Object|null} SoftKeyboard instance or null on error
 */
function buildRussianKeyboard(xmlId, context, width, height, template) {
    const ThemeManagerInstance = ThemeManager.getInstance(context);
    const currentThemeTitle = ThemeManagerInstance.getCurrentThemeTitle();

    try {
        const attrs = template.keyboard.attrs;
        const rows = template.keyboard.rows;

        // Load SKB template
        const skbTemplateResId = resolveResId(attrs.skb_template, context);
        const skbPool = SkbPool.getInstance();
        const skbTemplate = skbPool.getSkbTemplate(skbTemplateResId, context);

        if (!skbTemplate) {
            logger.error(
                `${ERROR.SKB_TEMPLATE_NOT_FOUND} ${attrs.skb_template} (ID: ${skbTemplateResId})`
            );
            return null;
        }

        // Create keyboard instance
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

        // Process keyboard rows
        for (const row of rows) {
            const rowId = row.row_id === undefined ? -1 : row.row_id;
            currentX = row.start_pos_x === undefined ? 0.0 : row.start_pos_x;
            currentY = row.start_pos_y === undefined ? currentY : row.start_pos_y;

            softKeyboard.beginNewRow(rowId, currentY);

            // Process keys in the row
            for (const keyJson of row.keys) {
                let softKey = null;
                const keyCode = keyJson.code === undefined ? 0 : keyJson.code;

                // 1. Key by ID (special keys from template)
                if (keyJson.id !== undefined) {
                    softKey = skbTemplate.getDefaultKey(keyJson.id);

                    if (!softKey) {
                        logger.debug(`${DEBUG.GET_DEFAULT_KEY_NULL} ${keyJson.id}`);
                        continue;
                    }
                } else if (keyJson.toggle_states) {
                    // 2. Key with toggle states (e.g., Shift, language switch)

                    softKey = SoftKeyToggle.$new();

                    // Create linked list of toggle states
                    let prevState = null;
                    let firstState = null;

                    for (const stateJson of keyJson.toggle_states) {
                        const state = softKey.createToggleState();

                        // Set state ID
                        const stateId = stateJson.state_id === undefined ? 0 : stateJson.state_id;
                        state.setStateId(stateId);

                        // Set key code
                        setFieldValue(
                            state,
                            'mKeyCode',
                            stateJson.code === undefined ? 0 : stateJson.code
                        );

                        // Set label
                        setFieldValue(
                            state,
                            'mKeyLabel',
                            stateJson.label === undefined ? null : stateJson.label
                        );
                        let stateIcon = null;

                        if (WHITE_THEME === currentThemeTitle) {
                            // White theme icons
                            if (keyCode === 0) {
                                switch (stateId) {
                                    case TOGGLE_STATE_LOWER:
                                        stateIcon = context.getDrawable(
                                            getFieldValue(R_drawable, 'shift_lower_c53_white')
                                        );
                                        break;
                                    case TOGGLE_STATE_UPPER:
                                        stateIcon = context.getDrawable(
                                            getFieldValue(R_drawable, 'shift_uppercase_c53_white')
                                        );
                                        break;
                                    case TOGGLE_STATE_TEMP_UPPER:
                                        stateIcon = context.getDrawable(
                                            getFieldValue(
                                                R_drawable,
                                                'shift_uppercase_c53_temp_white'
                                            )
                                        );
                                        break;
                                }
                            } else if (keyCode === KEY_CODE_LANGUAGE_SWITCH) {
                                if (
                                    stateId === TOGGLE_STATE_LOWER ||
                                    stateId === TOGGLE_STATE_UPPER ||
                                    stateId === TOGGLE_STATE_TEMP_UPPER
                                ) {
                                    if (
                                        Object.prototype.hasOwnProperty.call(
                                            drawableIcons,
                                            RU_INPUT_METHOD_WHITE_NAME
                                        )
                                    ) {
                                        stateIcon = drawableIcons[RU_INPUT_METHOD_WHITE_NAME];
                                    } else {
                                        stateIcon = context.getDrawable(
                                            getFieldValue(R_drawable, 'english_input_method_white')
                                        );
                                    }
                                }
                            }
                        } else {
                            // Dark theme icons
                            if (keyCode === KEY_CODE_LANGUAGE_SWITCH) {
                                if (
                                    stateId === TOGGLE_STATE_LOWER ||
                                    stateId === TOGGLE_STATE_UPPER ||
                                    stateId === TOGGLE_STATE_TEMP_UPPER
                                ) {
                                    if (
                                        Object.prototype.hasOwnProperty.call(
                                            drawableIcons,
                                            RU_INPUT_METHOD_NAME
                                        )
                                    ) {
                                        stateIcon = drawableIcons[RU_INPUT_METHOD_NAME];
                                    }
                                }
                            }
                        }

                        if (stateIcon !== null) {
                            setFieldValue(state, 'mKeyIcon', stateIcon);
                        } else if (stateJson.icon) {
                            const iconId = resolveResId(stateJson.icon, context);
                            if (iconId) {
                                setFieldValue(state, 'mKeyIcon', context.getDrawable(iconId));
                            }
                        }

                        if (stateJson.icon_popup) {
                            const iconPopupId = resolveResId(stateJson.icon_popup, context);
                            if (iconPopupId) {
                                setFieldValue(
                                    state,
                                    'mKeyIconPopup',
                                    context.getDrawable(iconPopupId)
                                );
                            }
                        }

                        // Set key type if specified
                        if (stateJson.key_type !== undefined) {
                            const stateKeyType = skbTemplate.getKeyType(stateJson.key_type);
                            setFieldValue(state, 'mKeyType', stateKeyType);
                        }

                        // Set flags
                        const stateRepeat =
                            stateJson.repeat !== undefined ? stateJson.repeat : attrs.repeat;
                        const stateBalloon =
                            stateJson.balloon !== undefined ? stateJson.balloon : attrs.balloon;

                        state.setStateFlags(stateRepeat, stateBalloon);

                        // Link states together
                        if (prevState) {
                            setFieldValue(prevState, 'mNextState', state);
                        } else {
                            firstState = state;
                        }

                        prevState = state;
                    }

                    // Set first state
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

                // Set popup keyboard ID
                if (keyJson.popup_skb) {
                    const popupSkbId = resolveResId(keyJson.popup_skb, context);
                    currentSoftKey.setPopupSkbId(popupSkbId);
                }

                // Set key type
                const keyTypeId =
                    keyJson.key_type === undefined ? attrs.key_type || 0 : keyJson.key_type;
                const keyType = skbTemplate.getKeyType(keyTypeId);

                // Get icons for the key
                let keyIcon = null;
                let keyIconPopup = null;

                if (keyCode === KEY_CODE_HIDE_KEYBOARD && WHITE_THEME === currentThemeTitle) {
                    keyIcon = context.getDrawable(getFieldValue(R_drawable, 'hide_keyboard_white'));
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

                // Set dimensions
                const keyWidth = keyJson.width == undefined ? attrs.width : keyJson.width;
                const keyHeight = attrs.height;

                const keyPositionX = currentX + keyWidth;
                const keyPositionY = currentY + keyHeight;

                // Validate minimum size
                if (
                    keyPositionX - currentX < attrs.key_xmargin * 2.0 ||
                    keyPositionY - currentY < attrs.key_ymargin * 2.0
                ) {
                    logger.debug(
                        `${DEBUG.KEY_TOO_SMALL} ${keyJson.label || keyJson.id || 'unknown'}`
                    );
                    continue;
                }

                currentSoftKey.setKeyDimensions(currentX, currentY, keyPositionX, keyPositionY);

                currentSoftKey.setSkbCoreSize(width, height);
                currentSoftKey.changeCase(false);

                currentX = keyPositionX;

                if (!softKeyboard.addSoftKey(currentSoftKey)) {
                    logger.error(
                        `${ERROR.FAILED_TO_ADD_KEY} ${keyJson.label || keyJson.id || 'unknown'}`
                    );
                }
            }

            currentY += attrs.height;
        }

        // Note: getTooggleStateForCnCand() appears to be a typo in the Java API itself
        const toggleStateForCnCand = InputModeSwitcherInstance.getTooggleStateForCnCand();
        const toggleStates = InputModeSwitcherInstance.getToggleStates();

        softKeyboard.disableToggleState(toggleStateForCnCand, false);
        softKeyboard.enableToggleStates(toggleStates);

        softKeyboard.setSkbCoreSize(width, height);

        return softKeyboard;
    } catch (e) {
        logger.error(`${ERROR.KEYBOARD_BUILD_ERROR} ${e}`);
        return null;
    }
}

/**
 * Retrieves the Russian keyboard from the keyboard cache.
 *
 * Searches through the cached keyboards in SkbPool to find the Russian keyboard
 * instance identified by KEYBOARD_CACHE_ID.
 *
 * @returns {Object|null} Cached SoftKeyboard instance or null if not found
 */
function getKeyboardFromCache() {
    const mSoftKeyboards = getFieldValue(SkbPoolInstance, 'mSoftKeyboards');

    for (let i = 0; i < mSoftKeyboards.size(); i++) {
        const softKeyboard = Java.cast(mSoftKeyboards.elementAt(i), SoftKeyboard);

        if (softKeyboard.getCacheId() === KEYBOARD_CACHE_ID) {
            return softKeyboard;
        }
    }
    return null;
}

/**
 * Switches the case (upper/lower) of all letter keys in the keyboard.
 *
 * Iterates through all keys in the keyboard rows and applies case transformation
 * to letter keys within the valid key code ranges.
 *
 * @param {Object} keyRows - Java List of KeyRow objects
 * @param {boolean} isUpper - True for uppercase, false for lowercase
 */
function switchSoftKeyMode(keyRows, isUpper) {
    for (let indexRow = 0; indexRow < keyRows.size(); indexRow++) {
        const row = Java.cast(keyRows.get(indexRow), KeyRow);

        for (let indexKey = 0; indexKey < getFieldValue(row, 'mSoftKeys').size(); indexKey++) {
            let softKey = Java.cast(getFieldValue(row, 'mSoftKeys').get(indexKey), SoftKey);

            let keyCode = softKey.getKeyCode();

            // Only process letter keys
            if (keyCode < KEY_CODE_MIN_LETTER) continue;
            if (keyCode > KEY_CODE_MAX_LETTER && keyCode < KEY_CODE_MIN_RUSSIAN) continue;
            if (keyCode > KEY_CODE_MAX_RUSSIAN) continue;

            softKey.changeCase(isUpper);
        }
    }
}

/**
 * Disables voice input functionality in the keyboard.
 *
 * Sets the DISABLE_VOICE flag in QGInputConfig to prevent voice input activation.
 */
function disableVoice() {
    const QGInputConfig = Java.use('com.qinggan.app.qgime.QGInputConfig');
    setFieldValue(QGInputConfig, 'DISABLE_VOICE', true);
}

/**
 * Resets the cached keyboard in SkbPool.
 *
 * Forces the keyboard pool to clear its cache, ensuring fresh keyboard instances
 * are created on next access.
 */
function resetCachedSkb() {
    SkbPoolInstance.resetCachedSkb();
}

/**
 * Hooks the getSoftKeyboard method to intercept keyboard loading.
 *
 * Intercepts keyboard requests and returns the Russian keyboard when currentLayout
 * is 'ru', otherwise returns the default English keyboard.
 */
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

                    getFieldValue(this, 'mSoftKeyboards').add(softKeyboard);
                } else {
                    softKeyboard.setSkbCoreSize(width, height);
                    softKeyboard.setNewlyLoadedFlag(false);
                }

                // return softKeyboard;
            } catch (e) {
                logger.error(`${ERROR.KEYBOARD_BUILD_ERROR} ${e}`);
                logger.error(e.stack);
            }
        }

        // Note: getTooggleStateForCnCand() appears to be a typo in the Java API itself
        const toggleStateForCnCand = InputModeSwitcherInstance.getTooggleStateForCnCand();
        const toggleStates = InputModeSwitcherInstance.getToggleStates();

        softKeyboard.disableToggleState(toggleStateForCnCand, false);
        softKeyboard.enableToggleStates(toggleStates);

        return softKeyboard;
    };
}

/**
 * Hooks the switchModeForUserKey method to handle language switching.
 *
 * Intercepts user key presses for mode switching (language, symbols, voice input)
 * and manages the transition between English and Russian layouts.
 */
function switchModeForUserKeyHook() {
    const QGToast = Java.use('com.pateo.material.dialog.QGToast');

    InputModeSwitcher.switchModeForUserKey.implementation = function (i, z) {
        const oldLayout = currentLayout;

        if (i === KEY_CODE_LANGUAGE_SWITCH) {
            // Language switch key
            if (
                getFieldValue(this, 'mInputMode') === enModeSymbol1 ||
                getFieldValue(this, 'mInputMode') === enModeSymbol2
            ) {
                currentLayout = 'en';
                needUpdateLayout = oldLayout !== currentLayout;
                return this.switchModeForUserKey.call(this, i, z);
            }

            currentLayout = currentLayout === 'en' ? 'ru' : 'en';
            const newIcon =
                currentLayout === 'ru' ? RUSSIAN_ICON : getFieldValue(R_drawable, 'ime_en');

            setFieldValue(this, 'mInputIcon', newIcon);
            needUpdateLayout = oldLayout !== currentLayout;

            return newIcon;
        } else if (i == KEY_CODE_SYMBOL_SWITCH) {
            currentLayout = 'en';
        } else if (i === KEY_CODE_VOICE_INPUT) {
            const message =
                currentLayout === 'ru'
                    ? 'Голосовой ввод недоступен для русского языка.'
                    : 'Voice input is not available for English.';

            QGToast.makeText
                .overload('android.content.Context', 'java.lang.CharSequence', 'int')
                .call(QGToast, getFieldValue(this, 'mImeService'), message, 2)
                .show();

            return getFieldValue(this, 'mInputIcon');
        }

        needUpdateLayout = oldLayout !== currentLayout;
        return this.switchModeForUserKey.call(this, i, z);
    };
}

/**
 * Hooks the updateInputMode method to trigger layout updates.
 *
 * Intercepts input mode updates and forces keyboard layout refresh when
 * the layout has changed (needUpdateLayout flag is set).
 */
function updateInputModeHook() {
    const SkbContainer = Java.use('com.qinggan.app.qgime.SkbContainer');

    SkbContainer.updateInputMode.implementation = function () {
        this.updateInputMode.call(this);

        if (needUpdateLayout) {
            this.updateSkbLayout();
            needUpdateLayout = false;
        }
    };
}

/**
 * Hooks the saveInputMode method to restrict saved modes to English modes only.
 *
 * Ensures that only English input modes are persisted, preventing Russian mode
 * from being saved as the default mode.
 */
function saveInputModeHook() {
    InputModeSwitcher.saveInputMode.implementation = function (mode) {
        if (
            mode !== enModeLower &&
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

/**
 * Hooks the processKey method to handle Russian character input.
 *
 * Intercepts key processing and translates QWERTY key codes to JCUKEN characters
 * when the Russian layout is active.
 */
function processKeyHook() {
    const EnglishInputProcessor = Java.use('com.qinggan.app.qgime.EnglishInputProcessor');

    EnglishInputProcessor.processKey.implementation = function (ic, event, isShift, commit) {
        if (currentLayout !== 'ru') {
            return this.processKey.call(this, ic, event, isShift, commit);
        }

        const keyCode = event.getKeyCode();
        const keyLabel = resolveKeyChar(keyCode, qwertyToJcuken);
        if (keyLabel === null) {
            return this.processKey.call(this, ic, event, isShift, commit);
        }

        const keyChar = isShift ? keyLabel.toUpperCase() : keyLabel.toLowerCase();

        if (commit) {
            ic.commitText(Java.use('java.lang.String').$new(keyChar), 1);
        }

        setFieldValue(this, 'mLastKeyCode', keyCode);
        return true;
    };
}

/**
 * Hooks the responseSoftKeyEvent method to handle Russian mode key events.
 *
 * Intercepts soft key events and manages special behavior for Russian layout,
 * including mode switching for Russian-specific keys.
 */
function responseSoftKeyEventHook() {
    QingganIME.responseSoftKeyEvent.implementation = function (softKey) {
        this.responseSoftKeyEvent.call(this, softKey);

        if (needUpdateLayout) {
            getFieldValue(this, 'mSkbContainer').updateInputMode();
            return;
        }

        if (currentLayout === 'ru') {
            let keyCode = softKey.getKeyCode();
            if (!getFieldValue(this, 'mInputModeSwitcher').isQwertyFirstMode()) return;

            if (isRussianKeyCode(keyCode)) {
                getFieldValue(this, 'mInputModeSwitcher').switchModeForUserKey(-1, true);
                this.resetToIdleState(false);
                getFieldValue(this, 'mSkbContainer').updateInputMode();
                return;
            }
        }
    };
}

/**
 * Hooks the switchQwertyMode method to apply case changes to Russian keys.
 *
 * Intercepts QWERTY mode switching and ensures Russian keys also change case
 * when the keyboard switches between upper and lower case modes.
 */
function switchQwertyModeHook() {
    SoftKeyboard.switchQwertyMode.implementation = function (i, isUpper) {
        this.switchQwertyMode.call(this, i, isUpper);

        if (currentLayout !== 'ru') return;

        const keyRows = getFieldValue(this, 'mKeyRows');

        switchSoftKeyMode(keyRows, isUpper);
    };
}

/**
 * Hooks the enableToggleStates method to synchronize Russian key states.
 *
 * Intercepts toggle state changes and ensures Russian keys are synchronized
 * with the current keyboard case state.
 */
function enableToggleStatesHook() {
    SoftKeyboard.enableToggleStates.implementation = function (toggleStates) {
        this.enableToggleStates.call(this, toggleStates);

        if (currentLayout !== 'ru') return;

        const isUpper = getFieldValue(this, 'mIsQwertyUpperCase');
        const keyRows = getFieldValue(this, 'mKeyRows');

        switchSoftKeyMode(keyRows, isUpper);
    };
}

/**
 * Hooks the loadKeyboard method to customize language switch icons.
 *
 * Intercepts keyboard loading and replaces the default language switch icons
 * with custom icons from the configuration for both white and dark themes.
 */
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

                if (softKeyToggle.getKeyCode() != KEY_CODE_LANGUAGE_SWITCH) continue;

                let toggleState = Java.cast(toggleStateField.get(softKeyToggle), ToggleState);

                let keyIcon = null;

                if (WHITE_THEME === currentThemeTitle) {
                    if (
                        Object.prototype.hasOwnProperty.call(
                            drawableIcons,
                            EN_INPUT_METHOD_WHITE_NAME
                        )
                    ) {
                        keyIcon = drawableIcons[EN_INPUT_METHOD_WHITE_NAME];
                    }
                } else {
                    if (Object.prototype.hasOwnProperty.call(drawableIcons, EN_INPUT_METHOD_NAME)) {
                        keyIcon = drawableIcons[EN_INPUT_METHOD_NAME];
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

/**
 * Hooks the getKeyLabel method to fix Enter key label in Russian mode.
 *
 * Intercepts key label retrieval for the Enter key in Russian mode to ensure
 * the correct label is displayed from the toggle state.
 */
function getKeyLabelHook() {
    SoftKeyToggle.getKeyLabel.implementation = function () {
        if (currentLayout !== 'ru') return this.getKeyLabel.call(this);
        if (getFieldValue(this, 'mKeyCode') !== KEY_CODE_ENTER) return this.getKeyLabel.call(this);

        const toggleState = this.getToggleState();
        if (toggleState === null) return this.getKeyLabel.call(this);

        return getFieldValue(toggleState, 'mKeyLabel');
    };
}

/**
 * Initializes Java class references and loads configuration.
 *
 * Sets up all necessary Java class references, loads keyboard templates and
 * configuration, and initializes the QWERTY to JCUKEN character mapping.
 */
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

    enModeLower = getFieldValue(InputModeSwitcher, 'MODE_SKB_ENGLISH_LOWER');
    enModeUpper = getFieldValue(InputModeSwitcher, 'MODE_SKB_ENGLISH_UPPER');
    enModeFirst = getFieldValue(InputModeSwitcher, 'MODE_SKB_ENGLISH_FIRST');
    enModeHkb = getFieldValue(InputModeSwitcher, 'MODE_HKB_ENGLISH');
    enModeSymbol1 = getFieldValue(InputModeSwitcher, 'MODE_SKB_SYMBOL1_EN');
    enModeSymbol2 = getFieldValue(InputModeSwitcher, 'MODE_SKB_SYMBOL2_EN');

    WHITE_THEME = getFieldValue(ThemeManager, 'DEFAULT_THEME_TITLE2');

    RUSSIAN_ICON = getFieldValue(R_drawable, 'ime_pinyin');

    // Load template config with full parameter support
    // Priority: 1) params.config, 2) params.configPath, 3) KEYBOARD_TEMPLATE_PATH
    template = loadConfig(KEYBOARD_TEMPLATE_PATH, logger);

    // Config is required for this agent
    if (!template) {
        logger.error(ERROR.CONFIG_NOT_AVAILABLE);
        return;
    }

    qwertyToJcuken = createQwertyToJcuken(template);

    // Load keyboard config with full parameter support
    // Priority: 1) params.config, 2) params.configPath, 3) KEYBOARD_RU_CONFIG_PATH
    const keyboardConfig = loadConfig(KEYBOARD_RU_CONFIG_PATH, logger);

    if (keyboardConfig) {
        drawableIcons = createDrawableIcons(JSON.stringify(keyboardConfig));
    }

    currentLayout = 'en';
}

/**
 * Main entry point for the agent.
 * Initializes all hooks and starts the keyboard modification agent.
 */
export function main() {
    logger.info(INFO.STARTING);

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

    try {
        loadKeyboardHook();
    } catch (e) {
        logger.error(`${ERROR.LOAD_KEYBOARD_HOOK_FAILED} ${e.message}`);
    }

    getKeyLabelHook();

    disableVoice();
    resetCachedSkb();

    logger.info(INFO.STARTED);
}

runAgent(main);

// Export for testing
export { createQwertyToJcuken, resolveKeyChar, isRussianKeyCode };
