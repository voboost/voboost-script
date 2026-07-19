import test from 'ava';
import {
    getConfig,
    loadConfig,
    parseConfig,
    parseAppConfig,
    runAgent,
    mockRpcForTests,
    cleanupMockRpc,
} from '../lib/utils.js';

// Mirrors the MAX_ICON_BYTES cap defined in lib/utils.js (256 KiB). It is not
// exported since it is an internal implementation detail of parseAppConfig,
// so tests recompute the same value here to exercise the boundary.
const MAX_ICON_BYTES = 256 * 1024;

// Store original console.log
const originalConsoleLog = console.log;

// === Test Helpers ===

function setFridaParams(params) {
    mockRpcForTests(params);
}

function clearFridaParams() {
    cleanupMockRpc();
}

function createMockLogger() {
    const logs = [];
    return {
        logs,
        debug: (msg) => logs.push({ level: 'debug', msg }),
        info: (msg) => logs.push({ level: 'info', msg }),
        error: (msg) => logs.push({ level: 'error', msg }),
    };
}

// Minimal Java bridge stub for parseAppConfig() tests. parseAppConfig() calls
// Java.use('android.util.Base64') / Java.use('android.graphics.BitmapFactory')
// unconditionally, so a global Java stub is required even for cases that never
// reach Base64.decode (e.g. an icon rejected by the size cap).
function mockJavaForTests() {
    globalThis.Java = {
        use(className) {
            if (className === 'android.util.Base64') {
                return {
                    DEFAULT: 0,
                    // Not a real Base64 decode - this stub only needs to return
                    // something array-like with a plausible byte length so the
                    // mocked BitmapFactory.decodeByteArray() below can report it.
                    decode: (str) => new Uint8Array(Math.floor((str.length * 3) / 4)),
                };
            }
            if (className === 'android.graphics.BitmapFactory') {
                return {
                    decodeByteArray: (bytes) => ({ decodedByteLength: bytes.length }),
                };
            }
            throw new Error(`mockJavaForTests: unexpected Java.use(${className})`);
        },
    };
}

function cleanupMockJava() {
    delete globalThis.Java;
}

// Mock console to prevent output during tests
function mockConsole() {
    console.log = () => {}; // Silent mock
}

// Restore console
function restoreConsole() {
    console.log = originalConsoleLog;
}

// Clean up after each test
test.afterEach(() => {
    clearFridaParams();
    cleanupMockJava();
    restoreConsole();
});

// Setup console mock before each test
test.beforeEach(() => {
    mockConsole();
});

// === parseConfig Tests ===

test('parseConfig parses valid JSON object', (t) => {
    const result = parseConfig('{"key": "value"}');
    t.deepEqual(result, { key: 'value' });
});

test('parseConfig parses valid JSON array', (t) => {
    const result = parseConfig('[1, 2, 3]');
    t.deepEqual(result, [1, 2, 3]);
});

test('parseConfig parses nested JSON structure', (t) => {
    const json = '{"apps":[{"package":"com.example","name":["App","Приложение"]}]}';
    const result = parseConfig(json);

    t.truthy(result);
    t.is(result.apps.length, 1);
    t.is(result.apps[0].package, 'com.example');
    t.deepEqual(result.apps[0].name, ['App', 'Приложение']);
});

test('parseConfig handles unicode content', (t) => {
    const result = parseConfig('{"name": "Яндекс Музыка", "emoji": "🎵"}');

    t.is(result.name, 'Яндекс Музыка');
    t.is(result.emoji, '🎵');
});

test('parseConfig returns null for invalid JSON', (t) => {
    const result = parseConfig('not valid json');
    t.is(result, null);
});

test('parseConfig returns null for truncated JSON', (t) => {
    const result = parseConfig('{"key":');
    t.is(result, null);
});

test('parseConfig returns null for empty string', (t) => {
    const result = parseConfig('');
    t.is(result, null);
});

// === getConfig Tests - Direct Config Object ===

test.serial('getConfig returns stringified config from params.config object', (t) => {
    setFridaParams({
        config: { api_key: 'test-key', units: 'metric' },
    });

    const result = getConfig('/default/path.json');
    const parsed = JSON.parse(result);

    t.is(parsed.api_key, 'test-key');
    t.is(parsed.units, 'metric');
});

test.serial('getConfig handles nested config objects', (t) => {
    setFridaParams({
        config: {
            apps: [{ package: 'com.example', name: ['App', 'Приложение'] }],
            settings: { enabled: true },
        },
    });

    const result = getConfig('/default/path.json');
    const parsed = JSON.parse(result);

    t.is(parsed.apps.length, 1);
    t.is(parsed.apps[0].package, 'com.example');
    t.is(parsed.settings.enabled, true);
});

test.serial('getConfig handles empty config object', (t) => {
    setFridaParams({ config: {} });

    const result = getConfig('/default/path.json');

    t.is(result, '{}');
});

// === getConfig Tests - Direct Config String ===

test.serial('getConfig returns config string as-is', (t) => {
    setFridaParams({
        config: '{"api_key":"test-key"}',
    });

    const result = getConfig('/default/path.json');

    t.is(result, '{"api_key":"test-key"}');
});

// === getConfig Tests - Priority ===

test.serial('getConfig prioritizes params.config over params.configPath', (t) => {
    setFridaParams({
        config: { source: 'direct' },
        configPath: '/custom/path.json',
    });

    const result = getConfig('/default/path.json');
    const parsed = JSON.parse(result);

    t.is(parsed.source, 'direct');
});

test.serial('getConfig returns null when no params and null defaultPath', (t) => {
    clearFridaParams();

    const result = getConfig(null);

    t.is(result, null);
});

test.serial('getConfig returns null when params is empty object and null defaultPath', (t) => {
    setFridaParams({});

    const result = getConfig(null);

    t.is(result, null);
});

// === getConfig Tests - Edge Cases ===

test.serial('getConfig skips undefined config value', (t) => {
    setFridaParams({ config: undefined });

    // Should fall through to defaultPath, which is null, so returns null
    const result = getConfig(null);

    t.is(result, null);
});

// === loadConfig Tests - Successful Loading ===

test.serial('loadConfig returns parsed object from params.config', (t) => {
    setFridaParams({
        config: { api_key: 'test-key', lang: 'ru' },
    });

    const result = loadConfig('/default/path.json');

    t.truthy(result);
    t.is(result.api_key, 'test-key');
    t.is(result.lang, 'ru');
});

test.serial('loadConfig handles complex weather config', (t) => {
    setFridaParams({
        config: {
            api_key: 'openweathermap-key',
            units: 'metric',
            lang: 'ru',
        },
    });

    const result = loadConfig('/data/local/tmp/test/weather-config.json');

    t.truthy(result);
    t.is(result.api_key, 'openweathermap-key');
    t.is(result.units, 'metric');
    t.is(result.lang, 'ru');
});

test.serial('loadConfig handles complex apps config', (t) => {
    setFridaParams({
        config: {
            apps: [
                {
                    package: 'ru.yandex.music',
                    name: ['Яндекс Музыка', 'Yandex Music'],
                    replace_bar: true,
                    original_package: ['com.qinggan.app.music'],
                    package_sub_type: 'MUSIC',
                },
            ],
        },
    });

    const result = loadConfig('/data/local/tmp/test/apps-config.json');

    t.truthy(result);
    t.is(result.apps.length, 1);
    t.is(result.apps[0].package, 'ru.yandex.music');
    t.is(result.apps[0].replace_bar, true);
});

test.serial('loadConfig handles complex media config', (t) => {
    setFridaParams({
        config: {
            media: {
                WECAR_FLOW: {
                    pageName: 'ru.yandex.music',
                    servicePageName: 'ru.yandex.music',
                    serviceName: 'ru.yandex.music.MusicService',
                    autoPlay: true,
                },
            },
        },
    });

    const result = loadConfig('/data/local/tmp/test/media-source-config.json');

    t.truthy(result);
    t.truthy(result.media.WECAR_FLOW);
    t.is(result.media.WECAR_FLOW.pageName, 'ru.yandex.music');
    t.is(result.media.WECAR_FLOW.autoPlay, true);
});

// === loadConfig Tests - Error Handling ===

test.serial('loadConfig returns null when no config available', (t) => {
    clearFridaParams();

    const result = loadConfig(null);

    t.is(result, null);
});

test.serial('loadConfig returns null for invalid JSON string config', (t) => {
    setFridaParams({
        config: 'not valid json {',
    });

    const result = loadConfig('/default/path.json');

    t.is(result, null);
});

// === loadConfig Tests - Custom Logger ===

test.serial('loadConfig uses custom logger when provided', (t) => {
    const mockLogger = createMockLogger();

    setFridaParams({
        config: { test: true },
    });

    loadConfig('/default/path.json', mockLogger);

    // Should have logged something
    t.true(mockLogger.logs.length > 0);
    // Should have info level log for successful load
    t.true(mockLogger.logs.some((l) => l.level === 'info'));
});

test.serial('loadConfig logs debug when no config available', (t) => {
    const mockLogger = createMockLogger();

    clearFridaParams();

    loadConfig(null, mockLogger);

    // Should have logged debug message about no config
    t.true(mockLogger.logs.some((l) => l.level === 'debug'));
});

// === Real-World Config Scenarios ===

test.serial('weather widget config scenario', (t) => {
    // Simulate voboost app passing weather config
    setFridaParams({
        config: {
            api_key: 'abc123def456',
            units: 'metric',
            lang: 'ru',
        },
    });

    const config = loadConfig('/data/local/tmp/test/weather-config.json');

    // Agent validation: config exists and has api_key
    t.truthy(config);
    t.truthy(config.api_key);
    t.is(config.api_key, 'abc123def456');
});

test.serial('keyboard template config scenario', (t) => {
    // Simulate voboost app passing keyboard template
    setFridaParams({
        config: {
            keyboard: {
                attrs: {
                    skb_template: '@xml/skb_template1',
                    width: 0.1,
                    height: 0.25,
                    key_xmargin: 0.003,
                    key_ymargin: 0.01,
                    repeat: false,
                    balloon: true,
                    qwerty: true,
                    qwerty_uppercase: false,
                },
                rows: [
                    {
                        row_id: 0,
                        start_pos_y: 0.0,
                        keys: [
                            { code: 45, label: 'й', width: 0.1 },
                            { code: 51, label: 'ц', width: 0.1 },
                        ],
                    },
                ],
            },
        },
    });

    const config = loadConfig('/data/local/tmp/test/skb-qwerty-ru-no-voice.json');

    // Agent validation: config exists and has keyboard structure
    t.truthy(config);
    t.truthy(config.keyboard);
    t.truthy(config.keyboard.attrs);
    t.truthy(config.keyboard.rows);
    t.is(config.keyboard.rows.length, 1);
});

test.serial('app launcher config scenario', (t) => {
    // Simulate voboost app passing apps config
    setFridaParams({
        config: {
            apps: [
                {
                    package: 'ru.yandex.music',
                    name: ['Яндекс Музыка', 'Yandex Music'],
                    icon_big: 'base64encodedicon...',
                    replace_bar: true,
                    original_package: ['com.qinggan.app.music'],
                    package_sub_type: 'MUSIC',
                },
                {
                    package: 'com.spotify.music',
                    name: ['Spotify', 'Spotify'],
                    replace_bar: false,
                    package_sub_type: 'MUSIC',
                },
            ],
        },
    });

    const config = loadConfig('/data/local/tmp/test/apps-config.json');

    // Agent validation: config exists and has apps array
    t.truthy(config);
    t.truthy(config.apps);
    t.is(config.apps.length, 2);
    t.is(config.apps[0].package, 'ru.yandex.music');
    t.is(config.apps[1].package, 'com.spotify.music');
});

test.serial('missing required field scenario - weather without api_key', (t) => {
    // Config loads but agent should validate api_key
    setFridaParams({
        config: {
            units: 'metric',
            lang: 'ru',
            // Missing api_key!
        },
    });

    const config = loadConfig('/data/local/tmp/test/weather-config.json');

    // Config loads successfully
    t.truthy(config);
    // But api_key is missing - agent should check this
    t.falsy(config.api_key);
});

// === parseAppConfig Tests - Icon Size Cap (MAX_ICON_BYTES) ===

test.serial('parseAppConfig skips icon_big exceeding the size cap but keeps the app entry', (t) => {
    mockJavaForTests();

    const oversizedIcon = 'A'.repeat(MAX_ICON_BYTES + 1);
    const content = JSON.stringify({
        apps: [
            {
                package: 'com.example.oversized',
                name: ['App', 'App'],
                icon_big: oversizedIcon,
            },
        ],
    });

    const result = parseAppConfig(content);

    t.truthy(result);
    t.is(result.apps.length, 1);
    t.is(result.apps[0].package, 'com.example.oversized');
    // Icon over the cap is rejected (not decoded), rest of the entry survives.
    t.is(result.apps[0].icon_big, null);
});

test.serial(
    'parseAppConfig skips icon_small exceeding the size cap but keeps the app entry',
    (t) => {
        mockJavaForTests();

        const oversizedIcon = 'B'.repeat(MAX_ICON_BYTES + 1);
        const content = JSON.stringify({
            apps: [
                {
                    package: 'com.example.oversized-small',
                    name: ['App', 'App'],
                    icon_small: oversizedIcon,
                },
            ],
        });

        const result = parseAppConfig(content);

        t.truthy(result);
        t.is(result.apps.length, 1);
        // Icon over the cap is rejected; falling back to icon_big (also unset) stays null.
        t.is(result.apps[0].icon_small, null);
    }
);

test.serial(
    'parseAppConfig decodes icon_big that is exactly at the size cap (not rejected)',
    (t) => {
        mockJavaForTests();

        const atCapIcon = 'A'.repeat(MAX_ICON_BYTES);
        const content = JSON.stringify({
            apps: [
                {
                    package: 'com.example.atcap',
                    name: ['App', 'App'],
                    icon_big: atCapIcon,
                },
            ],
        });

        const result = parseAppConfig(content);

        t.truthy(result);
        t.is(result.apps.length, 1);
        // At the cap (not exceeding it) the icon is decoded, not skipped.
        t.truthy(result.apps[0].icon_big);
    }
);

test.serial('parseAppConfig decodes icon_big just under the size cap (not rejected)', (t) => {
    mockJavaForTests();

    const underCapIcon = 'A'.repeat(MAX_ICON_BYTES - 1);
    const content = JSON.stringify({
        apps: [
            {
                package: 'com.example.undercap',
                name: ['App', 'App'],
                icon_big: underCapIcon,
            },
        ],
    });

    const result = parseAppConfig(content);

    t.truthy(result);
    t.truthy(result.apps[0].icon_big);
});

// === runAgent Tests - Double-Start Guard (SCR-03) ===
//
// runAgent() skips auto-start when neither Java nor rpc are defined (plain
// Node.js test environment). To exercise the started-flag / initTimer guard
// itself, these tests stub globalThis.rpc so the guard lets runAgent proceed,
// then drive the init() / fallback-timer paths.

test.serial(
    'runAgent double-start guard: a second rpc.exports.init() call does not re-run main()',
    (t) => {
        const originalSetTimeout = globalThis.setTimeout;
        const originalClearTimeout = globalThis.clearTimeout;

        let capturedTimeoutCallback = null;
        let clearTimeoutCalls = 0;

        // Capture the fallback timer's callback instead of waiting 2s for it,
        // and count clearTimeout() calls to verify the timer is cancelled on
        // first start (and not touched again on subsequent no-op starts).
        globalThis.setTimeout = (fn, delay) => {
            capturedTimeoutCallback = fn;
            return originalSetTimeout(fn, delay);
        };
        globalThis.clearTimeout = (id) => {
            clearTimeoutCalls += 1;
            return originalClearTimeout(id);
        };

        let mainCallCount = 0;
        const main = () => {
            mainCallCount += 1;
        };

        // rpc presence makes runAgent proceed past the no-Frida guard.
        globalThis.rpc = { exports: {} };
        runAgent(main);

        // Simulate frida-inject calling init() (the normal startup path).
        globalThis.rpc.exports.init('early', { config: {} });
        t.is(mainCallCount, 1, 'main() must run after the first init() call');
        t.is(clearTimeoutCalls, 1, 'the fallback timer is cleared on first start');

        // Simulate a duplicate init() call (e.g. frida re-invoking init()).
        globalThis.rpc.exports.init('early', { config: {} });
        t.is(mainCallCount, 1, 'main() must not run again on a duplicate init() call');
        t.is(clearTimeoutCalls, 1, 'clearTimeout is not called again once already started');

        // Simulate the exact SCR-03 race: the fallback timer still fires even
        // though init() already ran and (in real usage) cleared it.
        t.truthy(capturedTimeoutCallback, 'fallback timer callback should have been captured');
        capturedTimeoutCallback();
        t.is(mainCallCount, 1, 'the started guard must block a stray fallback-timer start');

        globalThis.setTimeout = originalSetTimeout;
        globalThis.clearTimeout = originalClearTimeout;
        delete globalThis.rpc;
    }
);

test.serial(
    'runAgent double-start guard: fallback timer starts the agent only once when init() never fires',
    (t) => {
        const originalSetTimeout = globalThis.setTimeout;

        let capturedTimeoutCallback = null;

        globalThis.setTimeout = (fn, delay) => {
            capturedTimeoutCallback = fn;
            return originalSetTimeout(fn, delay);
        };

        let mainCallCount = 0;
        const main = () => {
            mainCallCount += 1;
        };

        // rpc presence makes runAgent proceed past the no-Frida guard.
        globalThis.rpc = { exports: {} };
        runAgent(main);

        t.truthy(capturedTimeoutCallback);

        // Fallback fires because init() was never called.
        capturedTimeoutCallback();
        t.is(mainCallCount, 1, 'main() runs once via the fallback timer');

        // If the fallback callback were somehow invoked again (or init() fired
        // late), the started guard must still prevent a second run.
        capturedTimeoutCallback();
        globalThis.rpc.exports.init('late', { config: {} });
        t.is(mainCallCount, 1, 'main() still only ran once');

        globalThis.setTimeout = originalSetTimeout;
        delete globalThis.rpc;
    }
);

test.serial('runAgent no-op: skips auto-start when neither Java nor rpc are present', (t) => {
    // Plain Node.js (no Java, no rpc): runAgent must NOT call main, set up
    // rpc.exports, or arm any timer. This is the structural replacement for
    // the former NODE_ENV === 'test' guard.
    let mainCallCount = 0;
    const main = () => {
        mainCallCount += 1;
    };

    // Confirm the precondition: neither global is defined here.
    t.is(typeof globalThis.Java, 'undefined');
    t.is(typeof globalThis.rpc, 'undefined');

    runAgent(main);
    t.is(mainCallCount, 0, 'main() must not run in a non-Frida environment');
});
