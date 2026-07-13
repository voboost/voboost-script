import test from 'ava';
import {
    isUserApp,
    filterLaunchableApps,
    EXCLUDED_PACKAGES,
} from '../agents/launcher-allapps-mod.js';

// Constants matching the agent
const FLAG_SYSTEM = 0x00000001;

// Tests for isUserApp()

test('isUserApp returns true for non-system app with launch intent', (t) => {
    t.is(isUserApp(0, true), true);
});

test('isUserApp returns false for non-system app without launch intent', (t) => {
    t.is(isUserApp(0, false), false);
});

test('isUserApp returns false for system app with launch intent', (t) => {
    t.is(isUserApp(FLAG_SYSTEM, true), false);
});

test('isUserApp returns false for system app without launch intent', (t) => {
    t.is(isUserApp(FLAG_SYSTEM, false), false);
});

test('isUserApp returns false for system app with other flags set', (t) => {
    const flags = FLAG_SYSTEM | 0x00000002 | 0x00000004;
    t.is(isUserApp(flags, true), false);
});

test('isUserApp returns true for app with other flags but not FLAG_SYSTEM', (t) => {
    const flags = 0x00000002 | 0x00000004;
    t.is(isUserApp(flags, true), true);
});

// Tests for filterLaunchableApps()

test('filterLaunchableApps returns empty array when existingPackages is null', (t) => {
    const result = filterLaunchableApps(null, [
        { packageName: 'com.test', flags: 0, hasLaunchIntent: true },
    ]);
    t.is(result.length, 0);
});

test('filterLaunchableApps returns empty array when installedApps is null', (t) => {
    const result = filterLaunchableApps({}, null);
    t.is(result.length, 0);
});

test('filterLaunchableApps returns empty array when installedApps is undefined', (t) => {
    const result = filterLaunchableApps({}, undefined);
    t.is(result.length, 0);
});

test('filterLaunchableApps returns empty array when installedApps is not an array', (t) => {
    const result = filterLaunchableApps({}, { packageName: 'com.test' });
    t.is(result.length, 0);
});

test('filterLaunchableApps returns empty array for empty installedApps', (t) => {
    const result = filterLaunchableApps({}, []);
    t.is(result.length, 0);
});

test('filterLaunchableApps returns launchable user apps not in existing', (t) => {
    const existing = { 'com.existing': true };
    const installed = [
        { packageName: 'com.existing', flags: 0, hasLaunchIntent: true },
        { packageName: 'com.new1', flags: 0, hasLaunchIntent: true },
        { packageName: 'com.new2', flags: 0, hasLaunchIntent: true },
    ];
    const result = filterLaunchableApps(existing, installed);
    t.is(result.length, 2);
    t.is(result[0], 'com.new1');
    t.is(result[1], 'com.new2');
});

test('filterLaunchableApps excludes system apps', (t) => {
    const existing = {};
    const installed = [
        { packageName: 'com.user', flags: 0, hasLaunchIntent: true },
        { packageName: 'com.system', flags: FLAG_SYSTEM, hasLaunchIntent: true },
    ];
    const result = filterLaunchableApps(existing, installed);
    t.is(result.length, 1);
    t.is(result[0], 'com.user');
});

test('filterLaunchableApps excludes apps without launch intent', (t) => {
    const existing = {};
    const installed = [
        { packageName: 'com.launchable', flags: 0, hasLaunchIntent: true },
        { packageName: 'com.nolaunch', flags: 0, hasLaunchIntent: false },
    ];
    const result = filterLaunchableApps(existing, installed);
    t.is(result.length, 1);
    t.is(result[0], 'com.launchable');
});

test('filterLaunchableApps handles apps with null packageName', (t) => {
    const existing = {};
    const installed = [
        { packageName: null, flags: 0, hasLaunchIntent: true },
        { packageName: 'com.valid', flags: 0, hasLaunchIntent: true },
    ];
    const result = filterLaunchableApps(existing, installed);
    t.is(result.length, 1);
    t.is(result[0], 'com.valid');
});

test('filterLaunchableApps handles apps with missing packageName', (t) => {
    const existing = {};
    const installed = [
        { flags: 0, hasLaunchIntent: true },
        { packageName: 'com.valid', flags: 0, hasLaunchIntent: true },
    ];
    const result = filterLaunchableApps(existing, installed);
    t.is(result.length, 1);
    t.is(result[0], 'com.valid');
});

test('filterLaunchableApps handles null app entries', (t) => {
    const existing = {};
    const installed = [null, { packageName: 'com.valid', flags: 0, hasLaunchIntent: true }];
    const result = filterLaunchableApps(existing, installed);
    t.is(result.length, 1);
    t.is(result[0], 'com.valid');
});

test('filterLaunchableApps with all apps filtered out', (t) => {
    const existing = {
        'com.app1': true,
        'com.app2': true,
    };
    const installed = [
        { packageName: 'com.app1', flags: 0, hasLaunchIntent: true },
        { packageName: 'com.app2', flags: 0, hasLaunchIntent: true },
    ];
    const result = filterLaunchableApps(existing, installed);
    t.is(result.length, 0);
});

test('filterLaunchableApps handles mixed scenario', (t) => {
    const existing = { 'com.existing': true };
    const installed = [
        { packageName: 'com.existing', flags: 0, hasLaunchIntent: true },
        { packageName: 'com.system', flags: FLAG_SYSTEM, hasLaunchIntent: true },
        { packageName: 'com.nolaunch', flags: 0, hasLaunchIntent: false },
        { packageName: 'com.valid1', flags: 0, hasLaunchIntent: true },
        { packageName: 'com.valid2', flags: 0x00000010, hasLaunchIntent: true },
    ];
    const result = filterLaunchableApps(existing, installed);
    t.is(result.length, 2);
    t.is(result[0], 'com.valid1');
    t.is(result[1], 'com.valid2');
});

// Tests for filterLaunchableApps() excludedPackages parameter

test('filterLaunchableApps defaults to no exclusions when excludedPackages is omitted', (t) => {
    const existing = {};
    const installed = [{ packageName: 'com.test', flags: 0, hasLaunchIntent: true }];
    const result = filterLaunchableApps(existing, installed);
    t.is(result.length, 1);
    t.is(result[0], 'com.test');
});

test('filterLaunchableApps excludes packages present in excludedPackages', (t) => {
    const existing = {};
    const excluded = { 'com.excluded': true };
    const installed = [
        { packageName: 'com.excluded', flags: 0, hasLaunchIntent: true },
        { packageName: 'com.included', flags: 0, hasLaunchIntent: true },
    ];
    const result = filterLaunchableApps(existing, installed, excluded);
    t.is(result.length, 1);
    t.is(result[0], 'com.included');
});

test('filterLaunchableApps excludes packages even when they would otherwise pass all other checks', (t) => {
    const existing = {};
    const excluded = { 'com.excluded': true };
    const installed = [{ packageName: 'com.excluded', flags: 0x00000010, hasLaunchIntent: true }];
    const result = filterLaunchableApps(existing, installed, excluded);
    t.is(result.length, 0);
});

test('filterLaunchableApps works with the real EXCLUDED_PACKAGES constant', (t) => {
    const existing = {};
    const installed = [
        { packageName: 'com.qinggan.app.launcher', flags: 0, hasLaunchIntent: true },
        { packageName: 'ru.voboost.inject', flags: 0, hasLaunchIntent: true },
        { packageName: 'com.thirdparty.app', flags: 0, hasLaunchIntent: true },
    ];
    const result = filterLaunchableApps(existing, installed, EXCLUDED_PACKAGES);
    t.is(result.length, 1);
    t.is(result[0], 'com.thirdparty.app');
});
