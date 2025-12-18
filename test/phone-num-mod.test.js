import test from 'ava';
import { getAmendNumber } from '../agents/phone-num-mod.js';

test('returns phone number unchanged when +86 prefix', (t) => {
    const result = getAmendNumber('+8613812345678');
    t.is(result, '+8613812345678');
});

test('returns phone number unchanged when no +86 prefix', (t) => {
    const result = getAmendNumber('13812345678');
    t.is(result, '13812345678');
});

test('handles phone number with whitespace', (t) => {
    const result = getAmendNumber(' +8613812345678 ');
    t.is(result, '+8613812345678');
});

test('handles empty string', (t) => {
    const result = getAmendNumber('');
    t.is(result, '');
});

test('preserves other country codes', (t) => {
    const result = getAmendNumber('+1234567890');
    t.is(result, '+1234567890');
});

test('handles number type input', (t) => {
    const result = getAmendNumber(8613812345678);
    t.is(result, '8613812345678');
});

test('handles whitespace-only string', (t) => {
    const result = getAmendNumber('   ');
    t.is(result, '');
});

test('handles +86 with no following digits', (t) => {
    const result = getAmendNumber('+86');
    t.is(result, '+86');
});
