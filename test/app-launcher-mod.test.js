import test from 'ava';
import { getLanguageIndex, filterNewApps } from '../agents/app-launcher-mod.js';

// Tests for getLanguageIndex()
test('getLanguageIndex returns 0 for EN locale', (t) => {
    const result = getLanguageIndex('EN');
    t.is(result, 0);
});

test('getLanguageIndex returns 1 for RU locale', (t) => {
    const result = getLanguageIndex('RU');
    t.is(result, 1);
});

test('getLanguageIndex returns 0 for EU locale', (t) => {
    const result = getLanguageIndex('EU');
    t.is(result, 0);
});

test('getLanguageIndex returns 0 for null locale', (t) => {
    const result = getLanguageIndex(null);
    t.is(result, 0);
});

test('getLanguageIndex returns 0 for undefined locale', (t) => {
    const result = getLanguageIndex(undefined);
    t.is(result, 0);
});

test('getLanguageIndex returns 0 for empty string', (t) => {
    const result = getLanguageIndex('');
    t.is(result, 0);
});

test('getLanguageIndex returns 0 for unknown locale', (t) => {
    const result = getLanguageIndex('FR');
    t.is(result, 0);
});

test('getLanguageIndex is case-sensitive', (t) => {
    const result = getLanguageIndex('en');
    t.is(result, 0);
});

test('getLanguageIndex handles lowercase ru', (t) => {
    const result = getLanguageIndex('ru');
    t.is(result, 0);
});

// Tests for filterNewApps()
test('filterNewApps returns apps not in existing packages', (t) => {
    const existingPackages = {
        'com.example.app1': true,
        'com.example.app2': true,
    };
    const configApps = [
        { package: 'com.example.app1' },
        { package: 'com.example.app3' },
        { package: 'com.example.app4' },
    ];
    const result = filterNewApps(existingPackages, configApps);
    t.is(result.length, 2);
    t.is(result[0].package, 'com.example.app3');
    t.is(result[1].package, 'com.example.app4');
});

test('filterNewApps returns empty array when all apps exist', (t) => {
    const existingPackages = {
        'com.example.app1': true,
        'com.example.app2': true,
    };
    const configApps = [{ package: 'com.example.app1' }, { package: 'com.example.app2' }];
    const result = filterNewApps(existingPackages, configApps);
    t.is(result.length, 0);
});

test('filterNewApps returns all apps when existing packages is empty', (t) => {
    const existingPackages = {};
    const configApps = [{ package: 'com.example.app1' }, { package: 'com.example.app2' }];
    const result = filterNewApps(existingPackages, configApps);
    t.is(result.length, 2);
    t.is(result[0].package, 'com.example.app1');
    t.is(result[1].package, 'com.example.app2');
});

test('filterNewApps returns empty array when configApps is empty', (t) => {
    const existingPackages = { 'com.example.app1': true };
    const configApps = [];
    const result = filterNewApps(existingPackages, configApps);
    t.is(result.length, 0);
});

test('filterNewApps returns empty array for null/undefined/non-array inputs', (t) => {
    const existingPackages = { 'com.example.app1': true };
    const configApps = [{ package: 'com.example.app1' }];

    // Null and undefined existingPackages
    t.is(filterNewApps(null, configApps).length, 0);
    t.is(filterNewApps(undefined, configApps).length, 0);

    // Null and undefined configApps
    t.is(filterNewApps(existingPackages, null).length, 0);
    t.is(filterNewApps(existingPackages, undefined).length, 0);

    // Both null
    t.is(filterNewApps(null, null).length, 0);

    // Non-array configApps
    t.is(filterNewApps(existingPackages, { package: 'com.example.app1' }).length, 0);
});

test('filterNewApps handles apps with additional properties', (t) => {
    const existingPackages = { 'com.example.app1': true };
    const configApps = [
        { package: 'com.example.app2', name: 'App 2', icon: 'icon.png' },
        { package: 'com.example.app3', name: 'App 3' },
    ];
    const result = filterNewApps(existingPackages, configApps);
    t.is(result.length, 2);
    t.is(result[0].package, 'com.example.app2');
    t.is(result[0].name, 'App 2');
    t.is(result[1].package, 'com.example.app3');
});

test('filterNewApps preserves app object structure', (t) => {
    const existingPackages = {};
    const configApps = [
        {
            package: 'com.example.app1',
            name: ['App 1 EN', 'App 1 RU'],
            icon_big: 'big.png',
            icon_small: 'small.png',
            package_sub_type: 1,
        },
    ];
    const result = filterNewApps(existingPackages, configApps);
    t.is(result.length, 1);
    t.deepEqual(result[0], configApps[0]);
});

test('filterNewApps handles mixed scenario with some existing and some new apps', (t) => {
    const existingPackages = {
        'com.example.app1': true,
        'com.example.app3': true,
        'com.example.app5': true,
    };
    const configApps = [
        { package: 'com.example.app1' },
        { package: 'com.example.app2' },
        { package: 'com.example.app3' },
        { package: 'com.example.app4' },
        { package: 'com.example.app5' },
        { package: 'com.example.app6' },
    ];
    const result = filterNewApps(existingPackages, configApps);
    t.is(result.length, 3);
    t.is(result[0].package, 'com.example.app2');
    t.is(result[1].package, 'com.example.app4');
    t.is(result[2].package, 'com.example.app6');
});

test('filterNewApps handles package names with special characters', (t) => {
    const existingPackages = { 'com.example.app-test_v1': true };
    const configApps = [
        { package: 'com.example.app-test_v1' },
        { package: 'com.example.app-test_v2' },
    ];
    const result = filterNewApps(existingPackages, configApps);
    t.is(result.length, 1);
    t.is(result[0].package, 'com.example.app-test_v2');
});

test('filterNewApps performs exact package name matching', (t) => {
    const existingPackages = { 'com.example.app': true };
    const configApps = [{ package: 'com.example.app' }, { package: 'com.example.app.extra' }];
    const result = filterNewApps(existingPackages, configApps);
    t.is(result.length, 1);
    t.is(result[0].package, 'com.example.app.extra');
});

test('filterNewApps deduplicates packages repeated within configApps', (t) => {
    const existingPackages = { 'com.example.existing': true };
    const configApps = [
        { package: 'com.example.dup' },
        { package: 'com.example.new' },
        { package: 'com.example.dup' },
        { package: 'com.example.new' },
    ];
    const result = filterNewApps(existingPackages, configApps);
    t.is(result.length, 2);
    t.is(result[0].package, 'com.example.dup');
    t.is(result[1].package, 'com.example.new');
});
