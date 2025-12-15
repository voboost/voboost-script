/**
 * Voboost Logger - Console-only implementation
 * Outputs to console with timestamps matching Kotlin format
 *
 * This file is bundled into each agent script by Rollup.
 * Usage: const logger = new Logger('module-name');
 */

/**
 * Logger class for module-specific logging
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
     * Log error message
     * @param {string} message - Error message
     */
    error(message) {
        console.log(`${this.getTimestamp()} [-] ${this.source}: ${message}`);
    }

    /**
     * Log info message
     * @param {string} message - Info message
     */
    info(message) {
        console.log(`${this.getTimestamp()} [+] ${this.source}: ${message}`);
    }

    /**
     * Log debug message
     * @param {string} message - Debug message
     */
    debug(message) {
        console.log(`${this.getTimestamp()} [*] ${this.source}: ${message}`);
    }
}
