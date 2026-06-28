import test from 'ava';
import { buildPageNameMap, init, mediaPageNames } from '../agents/media-key-mod.js';
import { mockRpcForTests, cleanupMockRpc } from '../lib/utils.js';

test.afterEach(() => {
    cleanupMockRpc();
});

test('builds page name map from valid config', (t) => {
    const config = {
        media: {
            spotify: { pageName: 'com.spotify.music', enabled: true },
            youtube: { pageName: 'com.google.youtube', enabled: false },
        },
    };

    const result = buildPageNameMap(config);

    t.deepEqual(result, {
        'com.spotify.music': { pageName: 'com.spotify.music', enabled: true },
        'com.google.youtube': { pageName: 'com.google.youtube', enabled: false },
    });
});

test('returns empty map for null config', (t) => {
    const result = buildPageNameMap(null);
    t.deepEqual(result, {});
});

test('returns empty map for undefined config', (t) => {
    const result = buildPageNameMap(undefined);
    t.deepEqual(result, {});
});

test('returns empty map for config without media property', (t) => {
    const config = { apps: [] };
    const result = buildPageNameMap(config);
    t.deepEqual(result, {});
});

test('returns empty map for config with null media property', (t) => {
    const config = { media: null };
    const result = buildPageNameMap(config);
    t.deepEqual(result, {});
});

test('returns empty map for empty media object', (t) => {
    const config = { media: {} };
    const result = buildPageNameMap(config);
    t.deepEqual(result, {});
});

test('skips entries with empty pageName', (t) => {
    const config = {
        media: {
            valid: { pageName: 'com.valid.app', enabled: true },
            empty: { pageName: '', enabled: true },
        },
    };

    const result = buildPageNameMap(config);

    t.deepEqual(result, {
        'com.valid.app': { pageName: 'com.valid.app', enabled: true },
    });
});

test('skips entries with whitespace-only pageName', (t) => {
    const config = {
        media: {
            valid: { pageName: 'com.valid.app', enabled: true },
            whitespace: { pageName: '   ', enabled: true },
        },
    };

    const result = buildPageNameMap(config);

    t.deepEqual(result, {
        'com.valid.app': { pageName: 'com.valid.app', enabled: true },
    });
});

test('skips entries with missing pageName property', (t) => {
    const config = {
        media: {
            valid: { pageName: 'com.valid.app', enabled: true },
            missing: { enabled: true },
        },
    };

    const result = buildPageNameMap(config);

    t.deepEqual(result, {
        'com.valid.app': { pageName: 'com.valid.app', enabled: true },
    });
});

test('skips entries with non-string pageName', (t) => {
    const config = {
        media: {
            valid: { pageName: 'com.valid.app', enabled: true },
            number: { pageName: 123, enabled: true },
            object: { pageName: { name: 'test' }, enabled: true },
        },
    };

    const result = buildPageNameMap(config);

    t.deepEqual(result, {
        'com.valid.app': { pageName: 'com.valid.app', enabled: true },
    });
});

test('skips null entries in media object', (t) => {
    const config = {
        media: {
            valid: { pageName: 'com.valid.app', enabled: true },
            nullEntry: null,
        },
    };

    const result = buildPageNameMap(config);

    t.deepEqual(result, {
        'com.valid.app': { pageName: 'com.valid.app', enabled: true },
    });
});

test('skips undefined entries in media object', (t) => {
    const config = {
        media: {
            valid: { pageName: 'com.valid.app', enabled: true },
            undefinedEntry: undefined,
        },
    };

    const result = buildPageNameMap(config);

    t.deepEqual(result, {
        'com.valid.app': { pageName: 'com.valid.app', enabled: true },
    });
});

test('handles page names with special characters', (t) => {
    const config = {
        media: {
            special: { pageName: 'com.example.app-test_v2.beta', enabled: true },
        },
    };

    const result = buildPageNameMap(config);

    t.deepEqual(result, {
        'com.example.app-test_v2.beta': { pageName: 'com.example.app-test_v2.beta', enabled: true },
    });
});

test('handles page names with dots and underscores', (t) => {
    const config = {
        media: {
            dotted: { pageName: 'com.example.app.activity.MainActivity', enabled: true },
            underscored: { pageName: 'com.example_app.test_activity', enabled: true },
        },
    };

    const result = buildPageNameMap(config);

    t.deepEqual(result, {
        'com.example.app.activity.MainActivity': {
            pageName: 'com.example.app.activity.MainActivity',
            enabled: true,
        },
        'com.example_app.test_activity': {
            pageName: 'com.example_app.test_activity',
            enabled: true,
        },
    });
});

test('preserves all properties of media entries', (t) => {
    const config = {
        media: {
            app1: {
                pageName: 'com.example.app',
                enabled: true,
                priority: 10,
                customField: 'value',
            },
        },
    };

    const result = buildPageNameMap(config);

    t.deepEqual(result, {
        'com.example.app': {
            pageName: 'com.example.app',
            enabled: true,
            priority: 10,
            customField: 'value',
        },
    });
});

test('handles duplicate page names (last one wins)', (t) => {
    const config = {
        media: {
            first: { pageName: 'com.example.app', priority: 1 },
            second: { pageName: 'com.example.app', priority: 2 },
        },
    };

    const result = buildPageNameMap(config);

    // JavaScript object iteration order is insertion order for string keys
    // The later entry with the same pageName overwrites the earlier one
    t.is(result['com.example.app'].priority, 2);
    t.is(Object.keys(result).length, 1);
});

test('handles large number of media entries', (t) => {
    const media = {};
    for (let i = 0; i < 100; i++) {
        media[`app${i}`] = { pageName: `com.example.app${i}`, enabled: true };
    }

    const config = { media };
    const result = buildPageNameMap(config);

    t.is(Object.keys(result).length, 100);
    t.truthy(result['com.example.app0']);
    t.truthy(result['com.example.app99']);
});

test('handles mixed valid and invalid entries', (t) => {
    const config = {
        media: {
            valid1: { pageName: 'com.valid1.app', enabled: true },
            empty: { pageName: '', enabled: true },
            valid2: { pageName: 'com.valid2.app', enabled: false },
            missing: { enabled: true },
            valid3: { pageName: 'com.valid3.app', enabled: true },
            whitespace: { pageName: '  ', enabled: true },
        },
    };

    const result = buildPageNameMap(config);

    t.is(Object.keys(result).length, 3);
    t.truthy(result['com.valid1.app']);
    t.truthy(result['com.valid2.app']);
    t.truthy(result['com.valid3.app']);
});

test('handles page names with leading/trailing whitespace', (t) => {
    const config = {
        media: {
            app: { pageName: '  com.example.app  ', enabled: true },
        },
    };

    const result = buildPageNameMap(config);

    // The function uses trim() check but stores the original value
    t.truthy(result['  com.example.app  ']);
});

test('handles config with media as empty array', (t) => {
    const config = { media: [] };
    const result = buildPageNameMap(config);
    t.deepEqual(result, {});
});

test('handles config with media as string', (t) => {
    const config = { media: 'invalid' };
    const result = buildPageNameMap(config);
    t.deepEqual(result, {});
});

test('handles config with media as number', (t) => {
    const config = { media: 123 };
    const result = buildPageNameMap(config);
    t.deepEqual(result, {});
});

// === init() Tests ===
//
// Regression coverage for the blocker where init() called parseConfig() a
// second time on the already-parsed object returned by loadConfig(). Since
// loadConfig() parses the raw config content internally, re-parsing its
// result with JSON.parse() coerces the object to the string
// "[object Object]", which fails to parse and yields a null config. That
// left mediaPageNames stuck at null, so every oriented-key event threw in
// handleOrientedKeyHook(). These tests exercise the real loadConfig() (via
// the Frida RPC mock helpers, the established pattern used in
// test/utils.test.js) to make sure init() populates mediaPageNames from the
// object loadConfig() returns, without any extra parsing step.

test.serial('init() populates mediaPageNames from the config loadConfig() returns', (t) => {
    mockRpcForTests({
        config: {
            media: {
                spotify: { pageName: 'com.spotify.music', enabled: true },
                youtube: { pageName: 'com.google.youtube', enabled: false },
            },
        },
    });

    init();

    t.deepEqual(mediaPageNames, {
        'com.spotify.music': { pageName: 'com.spotify.music', enabled: true },
        'com.google.youtube': { pageName: 'com.google.youtube', enabled: false },
    });
});
