import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './app-viewport-log.js';

import {
    LANGUAGE_CONFIG_PATH,
    APP_VIEWPORT_CONFIG_PATH,
    loadConfig,
    runAgent,
    setFieldValue,
    getFieldValue,
} from '../lib/utils.js';

const logger = new Logger('app-viewport-mod');

let SystemProperties = null;
let Rect = null;
let ActivityRecord = null;
let Locale = null;

let config = null;
let currentLocale = null;

// Screen dimension constants
const SCREEN_WIDTH = 1920;
const SCREEN_HEIGHT = 1080;
const SCREEN_BOTTOM_LOWERED = 530;
const SCREEN_BOTTOM_RAISED = 720;

// Padding constants
const PADDING_VALUES = {
    left: 145,
    up: 45,
    none: 0,
};

// 3. Функция получения текущего состояния экрана
function getScreenLiftState() {
    return SystemProperties.get('persist.qg.canbus.bcm_screenAutoLiftFdb') || '2';
}

/**
 * Resolves language configuration code to a standardized locale code.
 *
 * @param {string} languageCode - The language code from configuration (e.g., 'RU', 'EU', 'EN')
 * @returns {string} Standardized locale code: 'ru', 'eu', or 'en' (default)
 *
 * @example
 * resolveLocaleCode('RU'); // returns 'ru'
 * resolveLocaleCode('EU'); // returns 'eu'
 * resolveLocaleCode('EN'); // returns 'en'
 * resolveLocaleCode('UNKNOWN'); // returns 'en'
 */
function resolveLocaleCode(languageCode) {
    if (!languageCode) return 'en';

    const normalized = String(languageCode).toUpperCase();

    if (normalized === 'RU') return 'ru';
    if (normalized === 'EU') return 'eu';
    return 'en';
}

/**
 * Calculates viewport bounds based on padding configuration and screen lift state.
 *
 * @param {Object} params - Calculation parameters
 * @param {Array<string>} params.padding - Array of padding directions ('left', 'up')
 * @param {string} params.screenLift - Screen lift state: '1' (lowered), '2' (raised), or other
 * @returns {Object} Bounds object with left, top, right, bottom properties
 *
 * @example
 * calculateViewportBounds({ padding: ['left', 'up'], screenLift: '2' });
 * // returns { left: 145, top: 45, right: 1920, bottom: 720 }
 *
 * calculateViewportBounds({ padding: [], screenLift: '1' });
 * // returns { left: 0, top: 0, right: 1920, bottom: 530 }
 */
function calculateViewportBounds(params) {
    const { padding = [], screenLift = '2' } = params || {};

    let left = 0;
    let top = 0;
    let right = SCREEN_WIDTH;
    let bottom = SCREEN_HEIGHT;

    // Apply padding from configuration
    if (Array.isArray(padding)) {
        if (padding.includes('left')) left = PADDING_VALUES.left;
        if (padding.includes('up')) top = PADDING_VALUES.up;
    }

    // Adjust bottom based on screen lift state
    if (screenLift === '1') {
        bottom = SCREEN_BOTTOM_LOWERED; // Screen lowered
    } else if (screenLift === '2') {
        bottom = SCREEN_BOTTOM_RAISED; // Screen raised
    }

    return { left, top, right, bottom };
}

function createLocale(languageConfig) {
    const localeCode = resolveLocaleCode(languageConfig?.language);

    if (localeCode === 'ru') return Locale.$new('ru', 'RU');
    if (localeCode === 'eu') return Locale.$new('en', 'US');
    return Locale.$new('en', 'US');
}

// 4. Основная функция применения настроек к приложению
function applyAppSettings(activityRecord, displayId) {
    try {
        const packageName = getFieldValue(activityRecord, 'packageName');
        const currentDisplay = displayId === 0 ? 'main' : 'second';
        const screenLift = getScreenLiftState();

        // Поиск настроек для приложения
        const appConfig = config.apps.find((app) => app.package === packageName);
        if (!appConfig) return; // Пропускаем приложения не из конфига

        // Проверка разрешенных экранов
        if (!appConfig.screen.includes(currentDisplay)) return;

        // Вычисление границ с учетом состояния экрана
        const bounds = calculateViewportBounds({
            padding: appConfig.padding,
            screenLift: screenLift,
        });

        // Создание и применение новых границ
        const newBounds = Rect.$new(bounds.left, bounds.top, bounds.right, bounds.bottom);
        setFieldValue(activityRecord, 'mSizeCompatBounds', newBounds);

        // Применение масштаба
        setFieldValue(activityRecord, 'mSizeCompatScale', appConfig.scale);

        // Применение DPI и ориентации
        const configAR = activityRecord.getConfiguration();
        setFieldValue(configAR, 'densityDpi', appConfig.dpi);
        setFieldValue(configAR, 'orientation', 2); // Landscape всегда
        setFieldValue(configAR, 'locale', currentLocale);
        configAR.setLocale(currentLocale);
        activityRecord.onConfigurationChanged(configAR);

        logger.info(`${INFO.APPLIED_SETTINGS} ${packageName} on ${currentDisplay}`);
    } catch (e) {
        logger.error(`${ERROR.APPLYING_SETTINGS} ${e.message}`);
        logger.error(e.stack);
    }
}

function onDisplayChangedHook() {
    ActivityRecord.onDisplayChanged.overload(
        'com.android.server.wm.DisplayContent'
    ).implementation = function (displayContent) {
        try {
            // Вызов оригинального метода
            this.onDisplayChanged.call(this, displayContent);

            const displayId = displayContent.getDisplayId();
            applyAppSettings(this, displayId);
        } catch (e) {
            logger.error(`${ERROR.HOOK} ${e.message}`);
            logger.error(e.stack);
        }
    };
}

function init() {
    SystemProperties = Java.use('android.os.SystemProperties');
    Rect = Java.use('android.graphics.Rect');
    ActivityRecord = Java.use('com.android.server.wm.ActivityRecord');
    Locale = Java.use('java.util.Locale');
}

function main() {
    logger.info(INFO.STARTING);

    init();

    config = loadConfig(APP_VIEWPORT_CONFIG_PATH, logger);

    // Config is required for this agent
    if (!config) {
        logger.error(ERROR.CONFIG_NOT_AVAILABLE);
        return;
    }

    // Load language config with full parameter support
    // Priority: 1) params.config, 2) params.configPath, 3) LANGUAGE_CONFIG_PATH
    const languageConfig = loadConfig(LANGUAGE_CONFIG_PATH, logger);
    currentLocale = createLocale(languageConfig);

    onDisplayChangedHook();

    logger.info(INFO.STARTED);
}

runAgent(main);

// Export for testing
export {
    resolveLocaleCode,
    calculateViewportBounds,
    SCREEN_WIDTH,
    SCREEN_HEIGHT,
    SCREEN_BOTTOM_LOWERED,
    SCREEN_BOTTOM_RAISED,
    PADDING_VALUES,
};
