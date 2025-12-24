/**
 * Test setup: Patch Logger to disable info and debug output during tests
 * This file is loaded via AVA's require option before any tests run
 *
 * According to AGENTS.md: "никакие тесты не должны выводить в консоль, если нет ошибок"
 * This means tests should handle expected errors internally and not log them
 *
 * Usage:
 *   npm test              - error only (default, shows unexpected errors)
 *   LOG=info npm test     - error + info messages
 *   LOG=debug npm test    - all logging (for debugging)
 */
import { Logger } from './logger.js';

// Check LOG environment variable
// Values: 'debug' (all), 'info' (error+info), 'error' (default, error only)
const logLevel = process.env.LOG || 'error';

// Store original methods
const originalError = Logger.prototype.error;
const originalInfo = Logger.prototype.info;
const originalDebug = Logger.prototype.debug;

// Apply patches based on log level
// Default: show errors only (so we can see test failures)
if (logLevel === 'error') {
    Logger.prototype.info = function () {};
    Logger.prototype.debug = function () {};
} else if (logLevel === 'info') {
    // Show errors and info
    Logger.prototype.debug = function () {};
}

// If logLevel === 'debug', don't patch anything (show all)

// Export a function to restore all logging for logger tests
export function enableAllLogging() {
    Logger.prototype.error = originalError;
    Logger.prototype.info = originalInfo;
    Logger.prototype.debug = originalDebug;
}
