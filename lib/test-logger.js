/**
 * Test setup: cap the process-wide log level so tests stay silent on success.
 * Loaded via AVA's `require` option before any tests run.
 *
 * Per AGENTS.md/codestyle "tests MUST be silent on success", the default
 * level here is 'error' — info/debug calls from code-under-test produce no
 * output. The logger unit tests opt back into full verbosity via
 * enableAllLogging().
 *
 * Usage:
 *   npm test              - error only (default, shows unexpected errors)
 *   LOG=info npm test     - error + info messages
 *   LOG=debug npm test    - all logging (for debugging)
 */
import { setLogLevel, getLogLevel } from './logger.js';

// Values: 'debug' (all), 'info' (error+info), 'error' (default, error only)
const logLevel = process.env.LOG || 'error';
setLogLevel(logLevel);

// Restore full verbosity for the logger unit tests (which assert that
// info/debug actually emit). Returns the level that was active before the
// switch so the caller can restore it.
export function enableAllLogging() {
    const prev = getLogLevel();
    setLogLevel('debug');
    return prev;
}
