import { Logger } from './logger.js';
import { LOG } from './utils-log.js';

const logger = new Logger('utils');

export const LANGUAGE_CONFIG_PATH = '/data/local/tmp/test/language-config.json';
export const PHONE_NUM_CONFIG_PATH = '/data/local/tmp/test/phone-num-config.json';
export const APP_CONFIG_PATH = '/data/local/tmp/test/apps-config.json';
export const WEATHER_CONFIG_PATH = '/data/local/tmp/test/weather-config.json';
export const APP_VIEWPORT_CONFIG_PATH = '/data/local/tmp/test/apps-viewport-config.json';
export const KEYBOARD_TEMPLATE_PATH = '/data/local/tmp/test/skb-qwerty-ru-no-voice.json';
export const KEYBOARD_RU_CONFIG_PATH = '/data/local/tmp/test/keyboard-ru-config.json';
export const KEYBOARD_LOCK_EN_CONFIG_PATH = '/data/local/tmp/test/keyboard-lock-en-config.json';
export const MEDIA_SOURCE_CONFIG_PATH = '/data/local/tmp/test/media-source-config.json';

export function LoadTextFile(file) {
    const FileInputStream = Java.use('java.io.FileInputStream');
    const InputStreamReader = Java.use('java.io.InputStreamReader');
    const BufferedReader = Java.use('java.io.BufferedReader');

    const fis = FileInputStream.$new(file);
    const isr = InputStreamReader.$new(fis);
    const reader = BufferedReader.$new(isr);
    let line,
        content = '';
    while ((line = reader.readLine()) !== null) {
        content += line + '\n';
    }
    reader.close();
    return content;
}

export function parseConfig(content) {
    try {
        const config = JSON.parse(content);
        logger.info('Config loaded');
        return config;
    } catch (e) {
        logger.error(`Error loading config: ${e.message}`);
        return null;
    }
}

export function parseAppConfig(content) {
    try {
        const Base64 = Java.use('android.util.Base64');
        const BitmapFactory = Java.use('android.graphics.BitmapFactory');

        logger.debug(`Loading config: ${APP_CONFIG_PATH}`);

        //const content = LoadTextFile(APP_CONFIG_PATH);
        const config = JSON.parse(content);

        const items = config.apps.map((obj) => {
            const item = {
                package: obj.package,
                name: obj.name || ['', ''],
                icon_big: null,
                icon_small: null,
                replace_bar: obj.replace_bar || false,
                original_package: obj.original_package || [],
                package_sub_type: obj.package_sub_type || 'UNDEFINED',
            };

            if (obj.icon_big && obj.icon_big != '') {
                try {
                    const bytes = Base64.decode(obj.icon_big, Base64.DEFAULT.value);
                    item.icon_big = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
                    logger.debug(`Icon loaded for: ${obj.package}`);
                } catch {
                    logger.error(`Error decoding icon for ${obj.package}`);
                }
            }
            if (obj.icon_small && obj.icon_small != '') {
                try {
                    const bytes = Base64.decode(obj.icon_small, Base64.DEFAULT.value);
                    item.icon_small = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
                    logger.debug(`Icon loaded for: ${obj.package}`);
                } catch {
                    logger.error(`Error decoding icon for ${obj.package}`);
                }
            } else {
                item.icon_small = item.icon_big;
            }

            return item;
        });

        logger.info(`Config loaded: ${items.length} entries`);
        return { apps: items };
    } catch (e) {
        logger.error(`Error loading config: ${e.message}`);
        return null;
    }
}

/**
 * Gets configuration from multiple sources with priority:
 * 1. Direct config object in parameters (params.config = {...})
 * 2. Custom file path in parameters (params.configPath = "/path/to/config.json")
 * 3. Default file path (backward compatibility)
 *
 * @param {string} defaultPath - Default file path constant for backward compatibility
 * @returns {string|null} Configuration content as JSON string, or null if not available
 */
export function getConfig(defaultPath) {
    // Source 1: Direct config object passed via Frida parameters
    if (typeof globalThis !== 'undefined' && globalThis.__frida_params__) {
        const params = globalThis.__frida_params__;

        // Check for direct config object (highest priority)
        if (params.config !== undefined) {
            const config = params.config;

            logger.debug(LOG.CONFIG_FROM_PARAM);

            // If it's already an object, stringify it
            if (typeof config === 'object' && config !== null) {
                return JSON.stringify(config);
            }

            // If it's a string (JSON), return as-is
            if (typeof config === 'string') {
                return config;
            }
        }

        // Source 2: Custom file path passed via Frida parameters
        if (params.configPath) {
            const customPath = params.configPath;

            logger.debug(LOG.CONFIG_FROM_CUSTOM_PATH + customPath);

            return LoadTextFile(customPath);
        }
    }

    // Source 3: Default file path (backward compatibility)
    if (defaultPath) {
        try {
            logger.debug(LOG.CONFIG_FROM_DEFAULT_PATH + defaultPath);

            return LoadTextFile(defaultPath);
        } catch {
            logger.debug(LOG.CONFIG_DEFAULT_NOT_AVAILABLE + defaultPath);

            return null;
        }
    }

    return null;
}

/**
 * Safely loads and parses configuration with full error handling
 *
 * @param {string} defaultPath - Default file path for backward compatibility
 * @param {Object} [customLogger] - Optional custom logger instance
 * @returns {Object|null} Parsed configuration object, or null if not available
 *
 * @example
 * // In weather-widget-mod.js:
 * const config = loadConfig(WEATHER_CONFIG_PATH, logger);
 *
 * // Called with: frida -l agent.js --parameters '{"config": {"api_key": "xxx"}}'
 * // Or: frida -l agent.js --parameters '{"configPath": "/sdcard/config.json"}'
 * // Or: frida -l agent.js (uses WEATHER_CONFIG_PATH)
 */
export function loadConfig(defaultPath, customLogger = null) {
    const log = customLogger || logger;

    try {
        const content = getConfig(defaultPath);

        if (content === null) {
            log.debug(LOG.NO_CONFIG_AVAILABLE);
            return null;
        }

        const parsed = parseConfig(content);

        log.debug(LOG.CONFIG_LOADED);

        return parsed;
    } catch (e) {
        log.debug(LOG.CONFIG_LOAD_FAILED + e.message);

        return null;
    }
}
