import test from 'ava';
import {
    createQwertyToJcuken,
    resolveKeyChar,
    isRussianKeyCode,
} from '../agents/keyboard-ru-mod.js';

// Tests for createQwertyToJcuken
test('createQwertyToJcuken creates mapping from template', (t) => {
    const template = {
        keyboard: {
            rows: [
                {
                    keys: [
                        { code: 29, label: 'й' },
                        { code: 30, label: 'ц' },
                        { code: 31, label: 'у' },
                    ],
                },
                {
                    keys: [
                        { code: 44, label: 'ф' },
                        { code: 45, label: 'ы' },
                    ],
                },
            ],
        },
    };

    const result = createQwertyToJcuken(template);

    t.is(result[29], 'й');
    t.is(result[30], 'ц');
    t.is(result[31], 'у');
    t.is(result[44], 'ф');
    t.is(result[45], 'ы');
});

test('createQwertyToJcuken filters out keys below minimum code', (t) => {
    const template = {
        keyboard: {
            rows: [
                {
                    keys: [
                        { code: 28, label: 'x' }, // Below KEY_CODE_MIN_LETTER (29)
                        { code: 29, label: 'й' },
                    ],
                },
            ],
        },
    };

    const result = createQwertyToJcuken(template);

    t.is(result[28], undefined);
    t.is(result[29], 'й');
});

test('createQwertyToJcuken filters out keys in invalid range', (t) => {
    const template = {
        keyboard: {
            rows: [
                {
                    keys: [
                        { code: 54, label: 'a' }, // Valid
                        { code: 55, label: 'b' }, // Invalid range (55-10000)
                        { code: 10001, label: 'c' }, // Valid Russian range
                    ],
                },
            ],
        },
    };

    const result = createQwertyToJcuken(template);

    t.is(result[54], 'a');
    t.is(result[55], undefined);
    t.is(result[10001], 'c');
});

test('createQwertyToJcuken filters out keys above maximum code', (t) => {
    const template = {
        keyboard: {
            rows: [
                {
                    keys: [
                        { code: 10007, label: 'x' }, // Valid
                        { code: 10008, label: 'y' }, // Above KEY_CODE_MAX_RUSSIAN (10007)
                    ],
                },
            ],
        },
    };

    const result = createQwertyToJcuken(template);

    t.is(result[10007], 'x');
    t.is(result[10008], undefined);
});

test('createQwertyToJcuken skips keys without code', (t) => {
    const template = {
        keyboard: {
            rows: [
                {
                    keys: [
                        { label: 'й' }, // No code
                        { code: 30, label: 'ц' },
                    ],
                },
            ],
        },
    };

    const result = createQwertyToJcuken(template);

    t.is(result[30], 'ц');
    t.is(Object.keys(result).length, 1);
});

test('createQwertyToJcuken skips keys without label', (t) => {
    const template = {
        keyboard: {
            rows: [
                {
                    keys: [
                        { code: 29 }, // No label
                        { code: 30, label: 'ц' },
                    ],
                },
            ],
        },
    };

    const result = createQwertyToJcuken(template);

    t.is(result[29], undefined);
    t.is(result[30], 'ц');
});

test('createQwertyToJcuken skips keys with null label', (t) => {
    const template = {
        keyboard: {
            rows: [
                {
                    keys: [
                        { code: 29, label: null },
                        { code: 30, label: 'ц' },
                    ],
                },
            ],
        },
    };

    const result = createQwertyToJcuken(template);

    t.is(result[29], undefined);
    t.is(result[30], 'ц');
});

test('createQwertyToJcuken skips keys with empty label', (t) => {
    const template = {
        keyboard: {
            rows: [
                {
                    keys: [
                        { code: 29, label: '' },
                        { code: 30, label: 'ц' },
                    ],
                },
            ],
        },
    };

    const result = createQwertyToJcuken(template);

    t.is(result[29], undefined);
    t.is(result[30], 'ц');
});

test('createQwertyToJcuken handles empty rows', (t) => {
    const template = {
        keyboard: {
            rows: [],
        },
    };

    const result = createQwertyToJcuken(template);

    t.deepEqual(result, {});
});

test('createQwertyToJcuken handles rows with empty keys', (t) => {
    const template = {
        keyboard: {
            rows: [
                {
                    keys: [],
                },
            ],
        },
    };

    const result = createQwertyToJcuken(template);

    t.deepEqual(result, {});
});

// Tests for resolveKeyChar
test('resolveKeyChar returns character for valid key code', (t) => {
    const mapping = { 29: 'й', 30: 'ц', 31: 'у' };

    t.is(resolveKeyChar(29, mapping), 'й');
    t.is(resolveKeyChar(30, mapping), 'ц');
    t.is(resolveKeyChar(31, mapping), 'у');
});

test('resolveKeyChar returns null for invalid key code', (t) => {
    const mapping = { 29: 'й', 30: 'ц' };

    t.is(resolveKeyChar(999, mapping), null);
    t.is(resolveKeyChar(0, mapping), null);
    t.is(resolveKeyChar(-1, mapping), null);
});

test('resolveKeyChar returns null for null mapping', (t) => {
    t.is(resolveKeyChar(29, null), null);
});

test('resolveKeyChar returns null for undefined mapping', (t) => {
    t.is(resolveKeyChar(29, undefined), null);
});

test('resolveKeyChar returns null for non-object mapping', (t) => {
    t.is(resolveKeyChar(29, 'not an object'), null);
    t.is(resolveKeyChar(29, 123), null);
    t.is(resolveKeyChar(29, true), null);
});

test('resolveKeyChar returns null for non-number key code', (t) => {
    const mapping = { 29: 'й' };

    t.is(resolveKeyChar('29', mapping), null);
    t.is(resolveKeyChar(null, mapping), null);
    t.is(resolveKeyChar(undefined, mapping), null);
    t.is(resolveKeyChar({}, mapping), null);
});

test('resolveKeyChar handles empty mapping', (t) => {
    const mapping = {};

    t.is(resolveKeyChar(29, mapping), null);
});

test('resolveKeyChar handles mapping with zero key', (t) => {
    const mapping = { 0: 'zero' };

    t.is(resolveKeyChar(0, mapping), 'zero');
});

// Tests for isRussianKeyCode
test('isRussianKeyCode returns true for Russian key codes', (t) => {
    t.is(isRussianKeyCode(10001), true);
    t.is(isRussianKeyCode(10002), true);
    t.is(isRussianKeyCode(10003), true);
    t.is(isRussianKeyCode(10004), true);
    t.is(isRussianKeyCode(10005), true);
    t.is(isRussianKeyCode(10006), true);
    t.is(isRussianKeyCode(10007), true);
});

test('isRussianKeyCode returns false for codes below Russian range', (t) => {
    t.is(isRussianKeyCode(10000), false);
    t.is(isRussianKeyCode(9999), false);
    t.is(isRussianKeyCode(0), false);
    t.is(isRussianKeyCode(-1), false);
});

test('isRussianKeyCode returns false for codes above Russian range', (t) => {
    t.is(isRussianKeyCode(10008), false);
    t.is(isRussianKeyCode(10009), false);
    t.is(isRussianKeyCode(99999), false);
});

test('isRussianKeyCode returns false for non-number input', (t) => {
    t.is(isRussianKeyCode('10001'), false);
    t.is(isRussianKeyCode(null), false);
    t.is(isRussianKeyCode(undefined), false);
    t.is(isRussianKeyCode({}), false);
    t.is(isRussianKeyCode([]), false);
    t.is(isRussianKeyCode(true), false);
});

test('isRussianKeyCode returns false for NaN', (t) => {
    t.is(isRussianKeyCode(NaN), false);
});

test('isRussianKeyCode returns false for Infinity', (t) => {
    t.is(isRussianKeyCode(Infinity), false);
    t.is(isRussianKeyCode(-Infinity), false);
});

test('isRussianKeyCode handles boundary values correctly', (t) => {
    // Exactly at boundaries
    t.is(isRussianKeyCode(10001), true); // MIN
    t.is(isRussianKeyCode(10007), true); // MAX

    // Just outside boundaries
    t.is(isRussianKeyCode(10000), false); // MIN - 1
    t.is(isRussianKeyCode(10008), false); // MAX + 1
});
