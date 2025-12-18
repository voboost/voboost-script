import test from 'ava';
import { getAmendNumber } from '../agents/phone-num-mod.js';

test('phone number formatting - basic functionality', (t) => {
    // Test basic phone number formatting
    t.is(getAmendNumber('1234567890'), '1234567890');
    t.is(getAmendNumber('  1234567890  '), '1234567890');
    t.is(getAmendNumber(9876543210), '9876543210');
});

test('phone number formatting - with spaces', (t) => {
    // Test phone numbers with various spacing
    t.is(getAmendNumber(' 123 456 7890 '), '123 456 7890');
    t.is(getAmendNumber('\t5551234567\n'), '5551234567');
});

test('phone number formatting - international formats', (t) => {
    // Test international phone number formats
    t.is(getAmendNumber('+11234567890'), '+11234567890');
    t.is(getAmendNumber('+447911123456'), '+447911123456');
    t.is(getAmendNumber('  +33612345678  '), '+33612345678');
});

test('phone number formatting - edge cases', (t) => {
    // Test edge cases
    t.is(getAmendNumber(''), '');
    t.is(getAmendNumber('   '), '');
    t.is(getAmendNumber('123'), '123');
});
