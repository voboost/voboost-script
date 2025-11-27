import test from 'ava';
import { isMultiDisplayApp } from '../agents/app-multi-display.js';

test('returns true for app with multiple screens', (t) => {
    const apps = [
        { package: 'com.example.multiscreen', screen: ['main', 'third'] },
    ];
    const result = isMultiDisplayApp('com.example.multiscreen', apps);
    t.is(result, true);
});

test('returns false for app with single screen', (t) => {
    const apps = [
        { package: 'com.example.single', screen: ['main'] },
    ];
    const result = isMultiDisplayApp('com.example.single', apps);
    t.is(result, false);
});

test('returns null for package not in configuration', (t) => {
    const apps = [
        { package: 'com.example.app', screen: ['main', 'third'] },
    ];
    const result = isMultiDisplayApp('com.unknown.package', apps);
    t.is(result, null);
});

test('returns true for app with two screens', (t) => {
    const apps = [
        { package: 'com.example.dual', screen: ['main', 'third'] },
    ];
    const result = isMultiDisplayApp('com.example.dual', apps);
    t.is(result, true);
});

test('handles empty apps array', (t) => {
    const apps = [];
    const result = isMultiDisplayApp('com.example.app', apps);
    t.is(result, null);
});

test('finds correct app in multiple app configurations', (t) => {
    const apps = [
        { package: 'com.example.single', screen: ['main'] },
        { package: 'com.example.multi', screen: ['main', 'third'] },
        { package: 'com.example.another', screen: ['main'] },
    ];
    const result = isMultiDisplayApp('com.example.multi', apps);
    t.is(result, true);
});

test('returns false for first matching single-screen app', (t) => {
    const apps = [
        { package: 'com.example.app', screen: ['main'] },
        { package: 'com.example.app', screen: ['main', 'third'] },
    ];
    const result = isMultiDisplayApp('com.example.app', apps);
    t.is(result, false);
});

test('handles app with empty screen array', (t) => {
    const apps = [
        { package: 'com.example.noscreen', screen: [] },
    ];
    const result = isMultiDisplayApp('com.example.noscreen', apps);
    t.is(result, false);
});

test('performs exact package name matching', (t) => {
    const apps = [
        { package: 'com.example.app', screen: ['main', 'third'] },
    ];
    const result = isMultiDisplayApp('com.example.app.extra', apps);
    t.is(result, null);
});

test('handles package names with special characters', (t) => {
    const apps = [
        { package: 'com.example.app-test_v2', screen: ['main', 'third'] },
    ];
    const result = isMultiDisplayApp('com.example.app-test_v2', apps);
    t.is(result, true);
});
