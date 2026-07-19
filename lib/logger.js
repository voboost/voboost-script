/**
 * Voboost Logger - Console-only implementation with runtime log level.
 *
 * Outputs to console with timestamps matching Kotlin format. The level is
 * a process-wide runtime setting (shared by all Logger instances): call
 * `setLogLevel('error' | 'info' | 'debug')` once at startup to pick the
 * threshold. Default is 'info' so nothing is silenced by accident.
 *
 * This file is bundled into each agent script by Rollup.
 * Usage: const logger = new Logger('module-name');
 */

/**
 * Numeric weights for level comparison. Higher = more verbose.
 * error is always printed; info adds info; debug adds debug.
 */
const LEVEL_WEIGHT = {
    error: 1,
    info: 2,
    debug: 3,
};

/**
 * Current process-wide threshold weight. Shared across all Logger
 * instances so a single setLogLevel() call applies everywhere. Defaults
 * to 'info' (weight 2): errors and info print, debug is silent.
 */
let currentLevelWeight = LEVEL_WEIGHT.info;

/**
 * Sets the process-wide log level.
 *
 * @param {'error'|'info'|'debug'} level - Minimum level to print. Unknown
 *   values fall back to 'info'.
 * @returns {'error'|'info'|'debug'} The level that was actually applied.
 */
export function setLogLevel(level) {
    currentLevelWeight = LEVEL_WEIGHT[level] ?? LEVEL_WEIGHT.info;
    return getLogLevel();
}

/**
 * Gets the current process-wide log level name.
 *
 * @returns {'error'|'info'|'debug'} Current level name.
 */
export function getLogLevel() {
    for (const [name, weight] of Object.entries(LEVEL_WEIGHT)) {
        if (weight === currentLevelWeight) return name;
    }
    return 'info';
}

/**
 * Logger class for module-specific logging.
 */
export class Logger {
    /**
     * Create a logger instance
     * @param {string} source - Source identifier (module/agent name)
     */
    constructor(source) {
        this.source = source;
    }

    /**
     * Get timestamp in Kotlin-compatible format
     * Format: "YYYY-MM-DD HH:mm:ss.SSS"
     * @private
     */
    getTimestamp() {
        const now = new Date();
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        const hours = String(now.getHours()).padStart(2, '0');
        const minutes = String(now.getMinutes()).padStart(2, '0');
        const seconds = String(now.getSeconds()).padStart(2, '0');
        const ms = String(now.getMilliseconds()).padStart(3, '0');

        return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}.${ms}`;
    }

    /**
     * Log error message. Always printed (error is the lowest threshold).
     * @param {string} message - Error message
     */
    error(message) {
        if (currentLevelWeight < LEVEL_WEIGHT.error) return;
        console.log(`${this.getTimestamp()} [-] ${this.source}: ${message}`);
    }

    /**
     * Log info message. Printed when level is 'info' or 'debug'.
     * @param {string} message - Info message
     */
    info(message) {
        if (currentLevelWeight < LEVEL_WEIGHT.info) return;
        console.log(`${this.getTimestamp()} [+] ${this.source}: ${message}`);
    }

    /**
     * Log debug message. Printed only when level is 'debug'.
     * @param {string} message - Debug message
     */
    debug(message) {
        if (currentLevelWeight < LEVEL_WEIGHT.debug) return;
        console.log(`${this.getTimestamp()} [*] ${this.source}: ${message}`);
    }
}
