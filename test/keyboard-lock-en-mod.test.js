import test from 'ava';
import { isEnglishMode } from '../agents/keyboard-lock-en-mod.js';

const englishModes = {
    lower: 1,
    upper: 2,
    first: 3,
    hkb: 4,
    symbol1: 5,
    symbol2: 6,
};

// Test isEnglishMode function

test('returns true for English lowercase mode', (t) => {
    const result = isEnglishMode(1, englishModes);
    t.is(result, true);
});

test('returns true for English uppercase mode', (t) => {
    const result = isEnglishMode(2, englishModes);
    t.is(result, true);
});

test('returns true for English first letter uppercase mode', (t) => {
    const result = isEnglishMode(3, englishModes);
    t.is(result, true);
});

test('returns true for English hardware keyboard mode', (t) => {
    const result = isEnglishMode(4, englishModes);
    t.is(result, true);
});

test('returns true for English symbol mode 1', (t) => {
    const result = isEnglishMode(5, englishModes);
    t.is(result, true);
});

test('returns true for English symbol mode 2', (t) => {
    const result = isEnglishMode(6, englishModes);
    t.is(result, true);
});

test('returns false for non-English mode', (t) => {
    const result = isEnglishMode(99, englishModes);
    t.is(result, false);
});

test('returns false for null mode', (t) => {
    const result = isEnglishMode(null, englishModes);
    t.is(result, false);
});

test('returns false for undefined mode', (t) => {
    const result = isEnglishMode(undefined, englishModes);
    t.is(result, false);
});

test('returns false for null englishModes', (t) => {
    const result = isEnglishMode(1, null);
    t.is(result, false);
});

test('returns false for undefined englishModes', (t) => {
    const result = isEnglishMode(1, undefined);
    t.is(result, false);
});

test('returns false for string mode', (t) => {
    const result = isEnglishMode('1', englishModes);
    t.is(result, false);
});

test('returns false for object mode', (t) => {
    const result = isEnglishMode({ mode: 1 }, englishModes);
    t.is(result, false);
});

test('returns false for array mode', (t) => {
    const result = isEnglishMode([1], englishModes);
    t.is(result, false);
});

test('returns false for zero mode when not in English modes', (t) => {
    const result = isEnglishMode(0, englishModes);
    t.is(result, false);
});

test('returns true for zero mode when it is an English mode', (t) => {
    const modes = { ...englishModes, lower: 0 };
    const result = isEnglishMode(0, modes);
    t.is(result, true);
});

test('returns false for negative mode when not in English modes', (t) => {
    const result = isEnglishMode(-1, englishModes);
    t.is(result, false);
});

test('returns true for negative mode when it is an English mode', (t) => {
    const modes = { ...englishModes, lower: -1 };
    const result = isEnglishMode(-1, modes);
    t.is(result, true);
});

test('returns false for large number mode when not in English modes', (t) => {
    const result = isEnglishMode(999999, englishModes);
    t.is(result, false);
});

test('returns true for large number mode when it is an English mode', (t) => {
    const modes = { ...englishModes, lower: 999999 };
    const result = isEnglishMode(999999, modes);
    t.is(result, true);
});

test('returns false when englishModes is empty object', (t) => {
    const result = isEnglishMode(1, {});
    t.is(result, false);
});

test('returns false when mode is NaN', (t) => {
    const result = isEnglishMode(NaN, englishModes);
    t.is(result, false);
});

test('returns false when mode is Infinity', (t) => {
    const result = isEnglishMode(Infinity, englishModes);
    t.is(result, false);
});

test('returns false when mode is boolean true', (t) => {
    const result = isEnglishMode(true, englishModes);
    t.is(result, false);
});

test('returns false when mode is boolean false', (t) => {
    const result = isEnglishMode(false, englishModes);
    t.is(result, false);
});

test('handles englishModes with missing properties', (t) => {
    const modes = { lower: 1, upper: 2 };
    const result = isEnglishMode(1, modes);
    t.is(result, true);
});

test('returns false when checking mode not in partial englishModes', (t) => {
    const modes = { lower: 1, upper: 2 };
    const result = isEnglishMode(3, modes);
    t.is(result, false);
});
