import { Logger } from './logger.js';
import { ERROR, INFO, DEBUG } from './utils-log.js';

const logger = new Logger('utils');
const runAgentLogger = new Logger('runAgent');

export const LANGUAGE_CONFIG_PATH = '/data/local/tmp/test/language-config.json';
export const PHONE_NUM_CONFIG_PATH = '/data/local/tmp/test/phone-num-config.json';
export const APP_CONFIG_PATH = '/data/local/tmp/test/apps-config.json';
export const WEATHER_CONFIG_PATH = '/data/local/tmp/test/weather-config.json';
export const APP_VIEWPORT_CONFIG_PATH = '/data/local/tmp/test/apps-viewport-config.json';
export const KEYBOARD_TEMPLATE_PATH = '/data/local/tmp/test/skb-qwerty-ru-no-voice.json';
export const KEYBOARD_RU_CONFIG_PATH = '/data/local/tmp/test/keyboard-ru-config.json';
export const KEYBOARD_LOCK_EN_CONFIG_PATH = '/data/local/tmp/test/keyboard-lock-en-config.json';
export const MEDIA_SOURCE_CONFIG_PATH = '/data/local/tmp/test/media-source-config.json';

// Internal parameter storage
let _rpcParams = null;

/**
 * Sets parameters received from rpc.exports.init()
 * Called internally by runAgent() and by test helpers
 * @internal
 */
export function setRpcParams(params) {
    _rpcParams = params;
}

/**
 * Gets parameters from rpc.exports.init()
 * Used by getConfig() to retrieve parameters
 * @returns {Object|null} Parameters object or null
 */
export function getRpcParams() {
    return _rpcParams;
}

// Universal field accessor for compatibility with different stub implementations
export function setFieldValue(obj, fieldName, value) {
    try {
        // Try original .value access first
        if (obj[fieldName] && obj[fieldName].value !== undefined) {
            obj[fieldName].value = value;
            return;
        }

        // Fallback to direct access
        obj[fieldName] = value;
    } catch {
        logger.error(ERROR.FIELD_VALUE_SET + `${fieldName} ${value}`);
    }
}

export function getFieldValue(obj, fieldName) {
    try {
        // Try original .value access first
        if (obj[fieldName] && obj[fieldName].value !== undefined) {
            return obj[fieldName].value;
        }

        // Fallback to direct access
        return obj[fieldName];
    } catch {
        logger.error(ERROR.FIELD_VALUE_GET + `${fieldName}`);
        return undefined;
    }
}

/**
 * Safely schedules a function on main thread with fallback for test environments
 *
 * This function tries to use Java.scheduleOnMainThread() first, and if it fails
 * (e.g., in test environments with epoll_wait errors), it falls back to direct execution.
 *
 * @param {Function} fn - Function to execute
 * @param {Object} [logger] - Optional logger instance for debug messages
 */
export function scheduleOnMainThreadSafe(fn, logger = null) {
    try {
        Java.scheduleOnMainThread(fn);
    } catch (e) {
        // Fallback for test environment - run directly
        if (logger) {
            logger.debug(DEBUG.SCHEDULE_MAIN_THREAD_SKIPPED + ` ${e.message}`);
        }

        // Execute directly as fallback
        fn();
    }
}

/**
 * Safely gets Android Context using ActivityThread
 *
 * This function tries to get the application context using ActivityThread
 * which is the recommended way to get context in Frida agents.
 *
 * @param {Object} [logger] - Optional logger instance for error messages
 * @returns {Object|null} Context object or null if unable to get it
 */
export function getAndroidContext(logger = null) {
    let context = null;

    try {
        // Use ActivityThread directly instead of ContextUtils
        const ActivityThread = Java.use('android.app.ActivityThread');

        context = ActivityThread.currentApplication().getApplicationContext();
    } catch (e) {
        if (logger) {
            logger.error(ERROR.CONTEXT_GET_FAILED + ` ${e.message}`);
        }
    }

    if (!context && logger) {
        logger.error(ERROR.CONTEXT_UNAVAILABLE);
    }

    return context;
}

/**
 * Safely registers a Java class with fallback for test environments
 *
 * This function tries to use Java.registerClass() with the provided className first,
 * and if it fails (e.g., in test environments with nested class issues), it falls back
 * to using Java.registerClass() with the fallbackClassName.
 *
 * @param {Object} classConfig - The class configuration object for Java.registerClass()
 * @param {string} fallbackClassName - The fallback class name to use for registration
 * @param {Object} [logger] - Optional logger instance for debug messages
 * @returns {Object} The registered class
 */
export function registerClassSafe(classConfig, fallbackClassName, logger = null) {
    const log = logger || globalThis.logger;

    if (log) {
        log.debug(
            `registerClassSafe called with: ${classConfig.name}, fallback: ${fallbackClassName}`
        );
    }

    try {
        // Try to use Java.registerClass with the main className first
        if (log) {
            log.debug(`Trying Java.registerClass with: ${classConfig.name}`);
        }
        const registeredClass = Java.registerClass(classConfig);

        if (log) {
            log.debug(`Successfully registered class: ${classConfig.name}`);
        }

        return registeredClass;
    } catch (e) {
        if (log) {
            log.debug(DEBUG.REGISTER_CLASS_FALLBACK_USED + classConfig.name);
            log.debug(ERROR.REGISTER_CLASS_FAILED + e.message);
        }

        // Fallback: Try to use existing class from Java environment
        try {
            if (log) {
                log.debug(`Trying Java.use with: ${fallbackClassName}`);
            }
            const existingClass = Java.use(fallbackClassName);

            if (log) {
                log.debug(`Using existing class: ${fallbackClassName}`);
            }

            return existingClass;
        } catch (existingError) {
            if (log) {
                log.error(
                    `Failed to use existing class ${fallbackClassName}: ${existingError.message}`
                );
            }

            // Final fallback: Return a mock object that works in test environment
            if (log) {
                log.debug(`Using mock class for: ${fallbackClassName}`);
            }

            return createMockClass(classConfig, fallbackClassName, log);
        }
    }
}

/**
 * Creates a mock class for test environments
 * @param {Object} classConfig - Original class configuration
 * @param {string} className - Class name
 * @param {Object} logger - Logger instance
 * @returns {Object} Mock class
 */
function createMockClass(classConfig, className, logger) {
    const mockClass = {
        $new: function () {
            return {
                $className: className,
                onClick: classConfig.methods?.onClick || function () {},
            };
        },
    };

    if (logger) {
        logger.debug(`Created mock class for: ${className}`);
    }

    return mockClass;
}

export function loadTextFile(file) {
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

export function parseConfig(content, customLogger = null) {
    const log = customLogger || logger;

    try {
        const config = JSON.parse(content);
        log.info('Config loaded');
        return config;
    } catch (e) {
        log.error(`Error loading config: ${e.message}`);
        return null;
    }
}

export function parseAppConfig(content) {
    try {
        const Base64 = Java.use('android.util.Base64');
        const BitmapFactory = Java.use('android.graphics.BitmapFactory');

        logger.debug(`Loading config: ${APP_CONFIG_PATH}`);

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

            if (obj.icon_big && obj.icon_big !== '') {
                try {
                    const bytes = Base64.decode(obj.icon_big, getFieldValue(Base64, 'DEFAULT'));
                    item.icon_big = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
                    logger.debug(`Icon loaded for: ${obj.package}`);
                } catch (e) {
                    logger.error(`Error decoding icon for ${obj.package}: ${e.message}`);
                }
            }
            if (obj.icon_small && obj.icon_small !== '') {
                try {
                    const bytes = Base64.decode(obj.icon_small, getFieldValue(Base64, 'DEFAULT'));
                    item.icon_small = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
                    logger.debug(`Icon loaded for: ${obj.package}`);
                } catch (e) {
                    logger.error(`Error decoding icon for ${obj.package}: ${e.message}`);
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
 * Runs a Frida agent with proper rpc.exports setup for parameter passing.
 *
 * This function:
 * 1. Sets up rpc.exports.init() to receive parameters from frida-inject --parameters
 * 2. Stores parameters for getConfig() to access
 * 3. Calls the agent's main function inside Java.perform()
 *
 * @param {Function} main - The agent's main function to execute
 *
 * @example
 * // In weather-widget-mod.js:
 * import { runAgent } from '../lib/utils.js';
 *
 * function main() {
 *     // Agent logic here
 * }
 *
 * runAgent(main);
 */
export function runAgent(main) {
    // Check if we're in a test environment - don't auto-start agents
    // Tests should explicitly call agent functions if needed
    if (typeof process !== 'undefined' && process.env && process.env.NODE_ENV === 'test') {
        runAgentLogger.debug('Test environment detected, not auto-starting agent');
        return;
    }

    // Helper function to start the agent
    const startAgent = () => {
        if (typeof Java !== 'undefined') {
            runAgentLogger.debug('Starting agent in Java.perform()');
            try {
                // Check if Java.use works before trying Java.perform
                Java.use('java.lang.Object');
                Java.perform(() => main());
            } catch (e) {
                runAgentLogger.debug(`Java.use() failed: ${e.message}`);
                runAgentLogger.debug('Starting agent directly as fallback');
                main();
            }
        } else {
            runAgentLogger.debug('Java not available, starting agent directly');
            // For stub testing - run directly without Java.perform()
            main();
        }
    };

    // Set up rpc.exports for parameter passing (only if rpc is available)
    if (typeof rpc !== 'undefined') {
        runAgentLogger.debug('Setting up rpc.exports');
        rpc.exports = {
            init(stage, parameters) {
                runAgentLogger.debug(
                    `rpc.exports.init() called with: ${JSON.stringify(parameters)}`
                );
                // Store parameters for getConfig() to access
                if (parameters) {
                    setRpcParams(parameters);
                }
                // Start the agent immediately
                startAgent();
            },
            dispose() {
                runAgentLogger.debug('rpc.exports.dispose() called');
                // Cleanup if needed
            },
        };

        // Add timeout to start agent anyway if init() not called
        const RPC_INIT_TIMEOUT_MS = 2000;
        setTimeout(() => {
            runAgentLogger.debug('Timeout reached, starting agent anyway');
            startAgent();
        }, RPC_INIT_TIMEOUT_MS);
    } else {
        runAgentLogger.debug('No rpc available, starting agent directly');
        // Support direct execution (for testing without frida-inject)
        // This handles the case when script is loaded directly without rpc.exports.init() being called
        startAgent();
    }
}

/**
 * Gets configuration from rpc.exports.init() parameters (set by frida-inject --parameters)
 *
 * This is the ONLY way to pass parameters:
 * - Production: frida-inject --parameters '{"config": {...}}'
 * - Tests: frida-inject --parameters '{"config": {...}}'
 *
 * @param {string} defaultPath - Default file path constant for backward compatibility
 * @returns {string|null} Configuration content as JSON string, or null if not available
 */
export function getConfig(defaultPath) {
    // Get parameters from rpc.exports.init() (frida-inject --parameters)
    const params = getRpcParams();

    if (params) {
        logger.debug('Found params from rpc.exports.init()');
        logger.debug(`Params found: ${JSON.stringify(params)}`);

        // Check for direct config object (highest priority)
        if (params.config !== undefined) {
            const config = params.config;

            logger.debug(INFO.CONFIG_FROM_PARAM);
            logger.debug(`Config type: ${typeof config}, value: ${JSON.stringify(config)}`);

            // If it's already an object, stringify it
            if (typeof config === 'object' && config !== null) {
                return JSON.stringify(config);
            }

            // If it's a string (JSON), return as-is
            if (typeof config === 'string') {
                return config;
            }
        }

        // Custom file path passed via Frida parameters
        if (params.configPath) {
            const customPath = params.configPath;

            logger.debug(INFO.CONFIG_FROM_CUSTOM_PATH + customPath);

            return loadTextFile(customPath);
        }
    }

    // Fallback: Default file path (backward compatibility)
    if (defaultPath) {
        try {
            logger.debug(INFO.CONFIG_FROM_DEFAULT_PATH + defaultPath);

            return loadTextFile(defaultPath);
        } catch {
            logger.debug(DEBUG.CONFIG_DEFAULT_NOT_AVAILABLE + defaultPath);

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
            log.debug(DEBUG.NO_CONFIG_AVAILABLE);
            return null;
        }

        return parseConfig(content, log);
    } catch (e) {
        log.debug(ERROR.CONFIG_LOAD_FAILED + e.message);

        return null;
    }
}

// === Test Helpers ===

/**
 * Mock rpc environment for testing
 * Sets up globalThis.rpc and stores parameters
 * @param {Object} params - Parameters to store
 */
export function mockRpcForTests(params) {
    // Mock rpc.exports.init() as it would be in Frida runtime
    globalThis.rpc = {
        exports: {},
    };

    // Call setRpcParams to simulate rpc.exports.init() behavior
    setRpcParams(params);
}

/**
 * Clean up mock rpc environment after testing
 */
export function cleanupMockRpc() {
    delete globalThis.rpc;
    // Clear internal params by setting to null
    setRpcParams(null);
}
