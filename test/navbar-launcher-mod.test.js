import test from 'ava';
import { findMatchingApp } from '../agents/navbar-launcher-mod.js';

// Tests for findMatchingApp()

test('findMatchingApp: returns matching app for valid package name', (t) => {
    const apps = [
        { package: 'com.example.app1', navigation_bar: true },
        { package: 'com.example.app2', navigation_bar: false },
    ];
    const result = findMatchingApp('com.example.app1', apps);
    t.deepEqual(result, { package: 'com.example.app1', navigation_bar: true });
});

test('findMatchingApp: returns null for non-existent package', (t) => {
    const apps = [{ package: 'com.example.app1', navigation_bar: true }];
    const result = findMatchingApp('com.example.nonexistent', apps);
    t.is(result, null);
});

test('findMatchingApp: returns null for null package name', (t) => {
    const apps = [{ package: 'com.example.app1', navigation_bar: true }];
    const result = findMatchingApp(null, apps);
    t.is(result, null);
});

test('findMatchingApp: returns null for undefined package name', (t) => {
    const apps = [{ package: 'com.example.app1', navigation_bar: true }];
    const result = findMatchingApp(undefined, apps);
    t.is(result, null);
});

test('findMatchingApp: returns null for null apps', (t) => {
    const result = findMatchingApp('com.example.app1', null);
    t.is(result, null);
});

test('findMatchingApp: returns null for undefined apps', (t) => {
    const result = findMatchingApp('com.example.app1', undefined);
    t.is(result, null);
});

test('findMatchingApp: returns null for empty apps array', (t) => {
    const apps = [];
    const result = findMatchingApp('com.example.app1', apps);
    t.is(result, null);
});

test('findMatchingApp: returns null for non-array apps', (t) => {
    const apps = 'not an array';
    const result = findMatchingApp('com.example.app1', apps);
    t.is(result, null);
});

test('findMatchingApp: finds correct app in multiple app configurations', (t) => {
    const apps = [
        { package: 'com.example.app1', navigation_bar: true },
        { package: 'com.example.app2', navigation_bar: false },
        { package: 'com.example.app3', navigation_bar: true },
    ];
    const result = findMatchingApp('com.example.app2', apps);
    t.deepEqual(result, { package: 'com.example.app2', navigation_bar: false });
});

test('findMatchingApp: performs exact package name matching (case sensitive)', (t) => {
    const apps = [{ package: 'com.example.app', navigation_bar: true }];
    const result = findMatchingApp('com.example.App', apps);
    t.is(result, null);
});

test('findMatchingApp: does not match partial package names', (t) => {
    const apps = [{ package: 'com.example.app', navigation_bar: true }];
    const result = findMatchingApp('com.example', apps);
    t.is(result, null);
});

test('findMatchingApp: does not match package name with extra suffix', (t) => {
    const apps = [{ package: 'com.example.app', navigation_bar: true }];
    const result = findMatchingApp('com.example.app.extra', apps);
    t.is(result, null);
});

test('findMatchingApp: handles package names with special characters', (t) => {
    const apps = [{ package: 'com.example.app-test_v2', navigation_bar: true }];
    const result = findMatchingApp('com.example.app-test_v2', apps);
    t.deepEqual(result, { package: 'com.example.app-test_v2', navigation_bar: true });
});

test('findMatchingApp: handles empty string package name', (t) => {
    const apps = [{ package: 'com.example.app', navigation_bar: true }];
    const result = findMatchingApp('', apps);
    t.is(result, null);
});

test('findMatchingApp: returns first matching app when duplicates exist', (t) => {
    const apps = [
        { package: 'com.example.app', navigation_bar: true },
        { package: 'com.example.app', navigation_bar: false },
    ];
    const result = findMatchingApp('com.example.app', apps);
    t.deepEqual(result, { package: 'com.example.app', navigation_bar: true });
});

test('findMatchingApp: handles numeric package name input', (t) => {
    const apps = [{ package: '12345', navigation_bar: true }];
    const result = findMatchingApp(12345, apps);
    t.deepEqual(result, { package: '12345', navigation_bar: true });
});
