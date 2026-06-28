import test from 'ava';
import { getAppNameLocalization } from '../agents/voboost-to-menu-mod.js';

// Voboost's own localized name happens to be identical ('Voboost') in both EN
// and RU, so tests using it alone cannot detect a broken implementation that
// e.g. ignores the language entirely and always returns the EN string, or one
// that mixes up EN/RU. This fixture map has genuinely different EN/RU values
// so the locale-parsing/branching logic (toUpperCase, split('_')[0], toString,
// actual language selection, unknown-locale fallback) gets real coverage.
const testAppLocalization = {
    EN: 'Weather Widget',
    RU: 'Виджет погоды',
};

test('returns Voboost for Russian locale', (t) => {
    const result = getAppNameLocalization('ru');
    t.is(result, 'Voboost');
});

test('returns Voboost for Russian locale with country code', (t) => {
    const result = getAppNameLocalization('ru_RU');
    t.is(result, 'Voboost');
});

test('returns Voboost for uppercase Russian locale', (t) => {
    const result = getAppNameLocalization('RU');
    t.is(result, 'Voboost');
});

test('returns Voboost for English locale', (t) => {
    const result = getAppNameLocalization('en');
    t.is(result, 'Voboost');
});

test('returns Voboost for English locale with country code', (t) => {
    const result = getAppNameLocalization('en_US');
    t.is(result, 'Voboost');
});

test('returns Voboost for English locale GB', (t) => {
    const result = getAppNameLocalization('en_GB');
    t.is(result, 'Voboost');
});

test('returns Voboost for uppercase English locale', (t) => {
    const result = getAppNameLocalization('EN');
    t.is(result, 'Voboost');
});

test('returns default Voboost for unknown locale', (t) => {
    const result = getAppNameLocalization('fr');
    t.is(result, 'Voboost');
});

test('returns default Voboost for European locale', (t) => {
    const result = getAppNameLocalization('eu');
    t.is(result, 'Voboost');
});

test('returns default Voboost for European locale with country code', (t) => {
    const result = getAppNameLocalization('eu_EU');
    t.is(result, 'Voboost');
});

test('returns default Voboost for null locale', (t) => {
    const result = getAppNameLocalization(null);
    t.is(result, 'Voboost');
});

test('returns default Voboost for undefined locale', (t) => {
    const result = getAppNameLocalization(undefined);
    t.is(result, 'Voboost');
});

test('returns default Voboost for empty string locale', (t) => {
    const result = getAppNameLocalization('');
    t.is(result, 'Voboost');
});

// --- Second fixture (genuinely different EN/RU values) ---
// These tests exercise real language branching, which is impossible to
// verify using Voboost's own name since it is identical in both languages.

test('fixture: returns EN localization for English locale', (t) => {
    const result = getAppNameLocalization('en', testAppLocalization);
    t.is(result, 'Weather Widget');
});

test('fixture: returns RU localization for Russian locale', (t) => {
    const result = getAppNameLocalization('ru', testAppLocalization);
    t.is(result, 'Виджет погоды');
});

test('fixture: returns RU localization for uppercase Russian locale', (t) => {
    const result = getAppNameLocalization('RU', testAppLocalization);
    t.is(result, 'Виджет погоды');
});

test('fixture: returns RU localization for Russian locale with country code', (t) => {
    const result = getAppNameLocalization('ru_RU', testAppLocalization);
    t.is(result, 'Виджет погоды');
});

test('fixture: returns EN localization for English locale with country code', (t) => {
    const result = getAppNameLocalization('en_US', testAppLocalization);
    t.is(result, 'Weather Widget');
});

test('fixture: falls back to EN localization for unknown locale', (t) => {
    const result = getAppNameLocalization('fr', testAppLocalization);
    t.is(result, 'Weather Widget');
});

test('fixture: falls back to EN localization for null locale', (t) => {
    const result = getAppNameLocalization(null, testAppLocalization);
    t.is(result, 'Weather Widget');
});

test('fixture: handles numeric locale input against fixture map', (t) => {
    const result = getAppNameLocalization(123, testAppLocalization);
    t.is(result, 'Weather Widget');
});

test('fixture: EN and RU localizations are distinct (sanity check)', (t) => {
    const en = getAppNameLocalization('en', testAppLocalization);
    const ru = getAppNameLocalization('ru', testAppLocalization);
    t.not(en, ru);
});
