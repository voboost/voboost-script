import test from 'ava';
import { resolveLocaleCode, calculateViewportBounds } from '../agents/app-viewport-mod.js';

// The screen/padding constants are covered indirectly by the
// calculateViewportBounds tests below, which assert the resulting bound
// values — no separate literal-echoing constant tests needed.

// === resolveLocaleCode Tests ===
test('resolveLocaleCode returns ru for RU', (t) => {
    const result = resolveLocaleCode('RU');
    t.is(result, 'ru');
});

test('resolveLocaleCode returns eu for EU', (t) => {
    const result = resolveLocaleCode('EU');
    t.is(result, 'eu');
});

test('resolveLocaleCode returns en for EN', (t) => {
    const result = resolveLocaleCode('EN');
    t.is(result, 'en');
});

test('resolveLocaleCode returns en for unknown language code', (t) => {
    const result = resolveLocaleCode('FR');
    t.is(result, 'en');
});

test('resolveLocaleCode returns en for null', (t) => {
    const result = resolveLocaleCode(null);
    t.is(result, 'en');
});

test('resolveLocaleCode returns en for undefined', (t) => {
    const result = resolveLocaleCode(undefined);
    t.is(result, 'en');
});

test('resolveLocaleCode returns en for empty string', (t) => {
    const result = resolveLocaleCode('');
    t.is(result, 'en');
});

test('resolveLocaleCode handles lowercase ru', (t) => {
    const result = resolveLocaleCode('ru');
    t.is(result, 'ru');
});

test('resolveLocaleCode handles lowercase eu', (t) => {
    const result = resolveLocaleCode('eu');
    t.is(result, 'eu');
});

test('resolveLocaleCode handles lowercase en', (t) => {
    const result = resolveLocaleCode('en');
    t.is(result, 'en');
});

test('resolveLocaleCode handles mixed case RU', (t) => {
    const result = resolveLocaleCode('Ru');
    t.is(result, 'ru');
});

test('resolveLocaleCode handles mixed case EU', (t) => {
    const result = resolveLocaleCode('eU');
    t.is(result, 'eu');
});

test('resolveLocaleCode handles number input', (t) => {
    const result = resolveLocaleCode(123);
    t.is(result, 'en');
});

test('resolveLocaleCode handles object input', (t) => {
    const result = resolveLocaleCode({ language: 'RU' });
    t.is(result, 'en');
});

// === calculateViewportBounds Tests ===
test('calculateViewportBounds returns default bounds with no padding and screen raised', (t) => {
    const result = calculateViewportBounds({ padding: [], screenLift: '2' });
    t.deepEqual(result, {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 720,
    });
});

test('calculateViewportBounds applies left padding', (t) => {
    const result = calculateViewportBounds({ padding: ['left'], screenLift: '2' });
    t.deepEqual(result, {
        left: 145,
        top: 0,
        right: 1920,
        bottom: 720,
    });
});

test('calculateViewportBounds applies up padding', (t) => {
    const result = calculateViewportBounds({ padding: ['up'], screenLift: '2' });
    t.deepEqual(result, {
        left: 0,
        top: 45,
        right: 1920,
        bottom: 720,
    });
});

test('calculateViewportBounds applies both left and up padding', (t) => {
    const result = calculateViewportBounds({ padding: ['left', 'up'], screenLift: '2' });
    t.deepEqual(result, {
        left: 145,
        top: 45,
        right: 1920,
        bottom: 720,
    });
});

test('calculateViewportBounds uses lowered bottom when screenLift is 1', (t) => {
    const result = calculateViewportBounds({ padding: [], screenLift: '1' });
    t.deepEqual(result, {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 530,
    });
});

test('calculateViewportBounds uses raised bottom when screenLift is 2', (t) => {
    const result = calculateViewportBounds({ padding: [], screenLift: '2' });
    t.deepEqual(result, {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 720,
    });
});

test('calculateViewportBounds uses full height for unknown screenLift state', (t) => {
    const result = calculateViewportBounds({ padding: [], screenLift: '3' });
    t.deepEqual(result, {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 1080,
    });
});

test('calculateViewportBounds uses full height for empty screenLift', (t) => {
    const result = calculateViewportBounds({ padding: [], screenLift: '' });
    t.deepEqual(result, {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 1080,
    });
});

test('calculateViewportBounds handles null params', (t) => {
    const result = calculateViewportBounds(null);
    t.deepEqual(result, {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 720,
    });
});

test('calculateViewportBounds handles undefined params', (t) => {
    const result = calculateViewportBounds(undefined);
    t.deepEqual(result, {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 720,
    });
});

test('calculateViewportBounds handles empty object', (t) => {
    const result = calculateViewportBounds({});
    t.deepEqual(result, {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 720,
    });
});

test('calculateViewportBounds handles null padding array', (t) => {
    const result = calculateViewportBounds({ padding: null, screenLift: '2' });
    t.deepEqual(result, {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 720,
    });
});

test('calculateViewportBounds handles undefined padding array', (t) => {
    const result = calculateViewportBounds({ padding: undefined, screenLift: '2' });
    t.deepEqual(result, {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 720,
    });
});

test('calculateViewportBounds ignores invalid padding values', (t) => {
    const result = calculateViewportBounds({ padding: ['invalid', 'unknown'], screenLift: '2' });
    t.deepEqual(result, {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 720,
    });
});

test('calculateViewportBounds handles padding with none value', (t) => {
    const result = calculateViewportBounds({ padding: ['none'], screenLift: '2' });
    t.deepEqual(result, {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 720,
    });
});

test('calculateViewportBounds handles mixed valid and invalid padding', (t) => {
    const result = calculateViewportBounds({ padding: ['left', 'invalid', 'up'], screenLift: '2' });
    t.deepEqual(result, {
        left: 145,
        top: 45,
        right: 1920,
        bottom: 720,
    });
});

test('calculateViewportBounds handles duplicate padding values', (t) => {
    const result = calculateViewportBounds({ padding: ['left', 'left', 'up'], screenLift: '2' });
    t.deepEqual(result, {
        left: 145,
        top: 45,
        right: 1920,
        bottom: 720,
    });
});

test('calculateViewportBounds combines all features correctly', (t) => {
    const result = calculateViewportBounds({ padding: ['left', 'up'], screenLift: '1' });
    t.deepEqual(result, {
        left: 145,
        top: 45,
        right: 1920,
        bottom: 530,
    });
});

test('calculateViewportBounds handles non-array padding', (t) => {
    const result = calculateViewportBounds({ padding: 'left', screenLift: '2' });
    t.deepEqual(result, {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 720,
    });
});

test('calculateViewportBounds handles empty padding array', (t) => {
    const result = calculateViewportBounds({ padding: [], screenLift: '1' });
    t.deepEqual(result, {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 530,
    });
});

test('calculateViewportBounds handles screenLift with leading/trailing spaces', (t) => {
    const result = calculateViewportBounds({ padding: [], screenLift: ' 1 ' });
    t.deepEqual(result, {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 1080,
    });
});

test('calculateViewportBounds handles numeric screenLift', (t) => {
    const result = calculateViewportBounds({ padding: [], screenLift: 1 });
    t.deepEqual(result, {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 1080,
    });
});
