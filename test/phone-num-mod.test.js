import test from 'ava';
import { removeChineseCountryCode } from '../agents/phone-num-mod.js';

test('removes +86 prefix from phone number with prefix', (t) => {
    const result = removeChineseCountryCode("+8613812345678");
    t.is(result, "13812345678");
});

test('returns phone number unchanged when no +86 prefix', (t) => {
    const result = removeChineseCountryCode("13812345678");
    t.is(result, "13812345678");
});

test('handles phone number with whitespace', (t) => {
    const result = removeChineseCountryCode(" +8613812345678 ");
    t.is(result, "13812345678");
});

test('handles empty string', (t) => {
    const result = removeChineseCountryCode("");
    t.is(result, "");
});

test('preserves other country codes', (t) => {
    const result = removeChineseCountryCode("+1234567890");
    t.is(result, "+1234567890");
});

test('handles number type input', (t) => {
    const result = removeChineseCountryCode(8613812345678);
    t.is(result, "8613812345678");
});

test('handles whitespace-only string', (t) => {
    const result = removeChineseCountryCode("   ");
    t.is(result, "");
});

test('handles +86 with no following digits', (t) => {
    const result = removeChineseCountryCode("+86");
    t.is(result, "");
});
