import test from 'ava';
import { Logger } from '../lib/logger.js';
import { enableAllLogging } from '../lib/test-logger.js';

// Enable all logging for logger tests
enableAllLogging();

// Store original console.log
const originalConsoleLog = console.log;
let consoleLogCalls = [];

// Helper to reset mocks
function resetMocks() {
    consoleLogCalls = [];
    console.log = (...args) => {
        consoleLogCalls.push(args.join(' '));
    };
}

// Helper to restore console
function restoreConsole() {
    console.log = originalConsoleLog;
}

// === Logger Class Tests ===

test('Logger constructor sets source', (t) => {
    const logger = new Logger('test-module');
    t.is(logger.source, 'test-module');
});

test('Logger.error logs with correct format', (t) => {
    resetMocks();

    const logger = new Logger('test-module');
    logger.error('Error occurred');

    t.is(consoleLogCalls.length, 1);
    t.true(consoleLogCalls[0].includes('[-]'));
    t.true(consoleLogCalls[0].includes('test-module'));
    t.true(consoleLogCalls[0].includes('Error occurred'));

    restoreConsole();
});

test('Logger.info logs with correct format', (t) => {
    resetMocks();

    const logger = new Logger('test-module');
    logger.info('Processing started');

    t.is(consoleLogCalls.length, 1);
    t.true(consoleLogCalls[0].includes('[+]'));
    t.true(consoleLogCalls[0].includes('test-module'));
    t.true(consoleLogCalls[0].includes('Processing started'));

    restoreConsole();
});

test('Logger.debug logs with correct format', (t) => {
    resetMocks();

    const logger = new Logger('test-module');
    logger.debug('Debug info');

    t.is(consoleLogCalls.length, 1);
    t.true(consoleLogCalls[0].includes('[*]'));
    t.true(consoleLogCalls[0].includes('test-module'));
    t.true(consoleLogCalls[0].includes('Debug info'));

    restoreConsole();
});

test('Logger formats all log levels correctly', (t) => {
    resetMocks();

    const logger = new Logger('test-module');
    logger.error('Error message');
    logger.info('Info message');
    logger.debug('Debug message');

    t.is(consoleLogCalls.length, 3);
    t.true(consoleLogCalls[0].includes('[-] test-module: Error message'));
    t.true(consoleLogCalls[1].includes('[+] test-module: Info message'));
    t.true(consoleLogCalls[2].includes('[*] test-module: Debug message'));

    restoreConsole();
});

// === Timestamp Tests ===

test('Logger includes timestamp in correct format', (t) => {
    resetMocks();

    const logger = new Logger('test-module');
    logger.info('test message');

    t.is(consoleLogCalls.length, 1);
    const timestampPart = consoleLogCalls[0].split(' ')[0] + ' ' + consoleLogCalls[0].split(' ')[1];
    const regex = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$/;
    t.true(regex.test(timestampPart));

    restoreConsole();
});

test('Logger timestamp has correct length', (t) => {
    resetMocks();

    const logger = new Logger('test-module');
    logger.info('test message');

    t.is(consoleLogCalls.length, 1);
    const timestampPart = consoleLogCalls[0].split(' ')[0] + ' ' + consoleLogCalls[0].split(' ')[1];
    t.is(timestampPart.length, 23); // YYYY-MM-DD HH:mm:ss.SSS

    restoreConsole();
});

// === Edge Cases ===

test('Logger handles empty source gracefully', (t) => {
    resetMocks();

    const logger = new Logger('');
    logger.info('test message');

    t.is(consoleLogCalls.length, 1);
    t.true(consoleLogCalls[0].includes(': test message'));

    restoreConsole();
});

test('Logger handles empty message gracefully', (t) => {
    resetMocks();

    const logger = new Logger('test-source');
    logger.info('');

    t.is(consoleLogCalls.length, 1);
    t.true(consoleLogCalls[0].includes('test-source:'));

    restoreConsole();
});

test('Logger handles special characters in message', (t) => {
    resetMocks();

    const message = 'Test with "quotes" and <brackets> and \n newlines';
    const logger = new Logger('test-source');
    logger.info(message);

    t.is(consoleLogCalls.length, 1);
    t.true(consoleLogCalls[0].includes('quotes'));
    t.true(consoleLogCalls[0].includes('brackets'));

    restoreConsole();
});

test('Logger handles unicode characters in message', (t) => {
    resetMocks();

    const message = 'Unicode: 日本語 中文 한국어 🎉';
    const logger = new Logger('test-source');
    logger.info(message);

    t.is(consoleLogCalls.length, 1);
    t.true(consoleLogCalls[0].includes('日本語'));
    t.true(consoleLogCalls[0].includes('🎉'));

    restoreConsole();
});

test('Logger handles very long messages', (t) => {
    resetMocks();

    const message = 'A'.repeat(10000);
    const logger = new Logger('test-source');
    logger.info(message);

    t.is(consoleLogCalls.length, 1);
    t.true(consoleLogCalls[0].length > 10000);

    restoreConsole();
});

test('Logger handles special characters in source', (t) => {
    resetMocks();

    const logger = new Logger('test-module-v2.0');
    logger.info('test message');

    t.is(consoleLogCalls.length, 1);
    t.true(consoleLogCalls[0].includes('test-module-v2.0'));

    restoreConsole();
});

// === Multiple Logger Instances ===

test('Multiple logger instances work independently', (t) => {
    resetMocks();

    const logger1 = new Logger('module-1');
    const logger2 = new Logger('module-2');

    logger1.info('Message from module 1');
    logger2.info('Message from module 2');

    t.is(consoleLogCalls.length, 2);
    t.true(consoleLogCalls[0].includes('module-1'));
    t.true(consoleLogCalls[1].includes('module-2'));

    restoreConsole();
});

test('Logger instances maintain separate sources', (t) => {
    const logger1 = new Logger('module-1');
    const logger2 = new Logger('module-2');

    t.is(logger1.source, 'module-1');
    t.is(logger2.source, 'module-2');
});

// === Integration Tests ===

test('Complete logging flow with all levels', (t) => {
    resetMocks();

    const logger = new Logger('integration-test');

    logger.error('Error occurred');
    logger.info('Processing started');
    logger.debug('Debug info');

    t.is(consoleLogCalls.length, 3);
    t.true(consoleLogCalls[0].includes('[-]'));
    t.true(consoleLogCalls[1].includes('[+]'));
    t.true(consoleLogCalls[2].includes('[*]'));
    t.true(consoleLogCalls[0].includes('integration-test'));
    t.true(consoleLogCalls[1].includes('integration-test'));
    t.true(consoleLogCalls[2].includes('integration-test'));

    restoreConsole();
});

test('Logger works with typical agent usage pattern', (t) => {
    resetMocks();

    const logger = new Logger('weather-widget-mod');

    logger.info('Agent started');
    logger.debug('Loading config');
    logger.info('Config loaded');
    logger.debug('Installing hooks');
    logger.info('Hooks installed');

    t.is(consoleLogCalls.length, 5);
    t.true(consoleLogCalls.every((log) => log.includes('weather-widget-mod')));

    restoreConsole();
});
