import test from 'ava';
import { Logger, setLogLevel, getLogLevel } from '../lib/logger.js';
import { enableAllLogging } from '../lib/test-logger.js';

// The logger tests need all three methods to emit, so flip to debug and
// remember the level each test should restore.
const previousLevel = enableAllLogging();

// Mock console.log per-test; restore on teardown.
const originalConsoleLog = console.log;
let calls = [];

function mockConsole() {
    calls = [];
    console.log = (...args) => {
        calls.push(args.join(' '));
    };
}

function restoreConsole() {
    console.log = originalConsoleLog;
}

test.afterEach(() => {
    restoreConsole();
    setLogLevel('debug');
});

// === setLogLevel / getLogLevel ===

test('getLogLevel returns the currently set level', (t) => {
    setLogLevel('error');
    t.is(getLogLevel(), 'error');
    setLogLevel('info');
    t.is(getLogLevel(), 'info');
    setLogLevel('debug');
    t.is(getLogLevel(), 'debug');
});

test('setLogLevel falls back to info for unknown values', (t) => {
    t.is(setLogLevel('verbose'), 'info');
    t.is(setLogLevel(''), 'info');
    t.is(setLogLevel(null), 'info');
    t.is(getLogLevel(), 'info');
});

test('setLogLevel returns the level that was applied', (t) => {
    t.is(setLogLevel('error'), 'error');
    t.is(setLogLevel('debug'), 'debug');
});

// === Threshold filtering ===

test('level=error: only error prints', (t) => {
    setLogLevel('error');
    mockConsole();

    const logger = new Logger('m');
    logger.error('e');
    logger.info('i');
    logger.debug('d');

    t.is(calls.length, 1);
    t.true(calls[0].includes('[-]'));
    t.true(calls[0].includes('e'));
});

test('level=info: error and info print, debug silent', (t) => {
    setLogLevel('info');
    mockConsole();

    const logger = new Logger('m');
    logger.error('e');
    logger.info('i');
    logger.debug('d');

    t.is(calls.length, 2);
    t.true(calls[0].includes('[-]') && calls[0].includes('e'));
    t.true(calls[1].includes('[+]') && calls[1].includes('i'));
});

test('level=debug: all three print', (t) => {
    setLogLevel('debug');
    mockConsole();

    const logger = new Logger('m');
    logger.error('e');
    logger.info('i');
    logger.debug('d');

    t.is(calls.length, 3);
    t.true(calls[0].includes('[-]'));
    t.true(calls[1].includes('[+]'));
    t.true(calls[2].includes('[*]'));
});

// === Shared across instances ===

test('setLogLevel affects all Logger instances (process-wide threshold)', (t) => {
    setLogLevel('error');
    mockConsole();

    const a = new Logger('a');
    const b = new Logger('b');
    a.info('from-a');
    b.debug('from-b');

    t.is(calls.length, 0, 'info and debug both suppressed at error level');

    setLogLevel('debug');
    a.info('from-a');
    b.debug('from-b');

    t.is(calls.length, 2);
    t.true(calls[0].includes('a'));
    t.true(calls[1].includes('b'));
});

// enableAllLogging() must return the level that was active BEFORE the switch
// (not the new 'debug' value) so callers can restore it. test-logger.js caps
// the default to 'error', so previousLevel here must be 'error'.
test('enableAllLogging returns the previously active level (not the new one)', (t) => {
    t.is(previousLevel, 'error');
    t.not(previousLevel, 'debug');
});

test('enableAllLogging: return value round-trips through setLogLevel', (t) => {
    setLogLevel('info');
    const prev = enableAllLogging();
    t.is(prev, 'info', 'returns the level active before the call');
    setLogLevel(prev);
    t.is(getLogLevel(), 'info');
    // Restore the debug level the rest of this file relies on.
    setLogLevel('debug');
});
