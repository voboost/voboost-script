import test from 'ava';
import {
    getSubscribeInfoResponse,
    getNoaLearnInfoResponse,
} from '../agents/adas-activation-mod.js';

// Both functions take no arguments and back a hooked native method's return
// value with a fixed literal (see agents/adas-activation-mod.js). There is no
// input space to exercise, so these are golden-value guards: they pin the exact
// contract handed to the hooked implementation so an accidental change to the
// spoofed subscription/NOA values is caught.

test('getSubscribeInfoResponse spoofs an active, non-expired 30-day subscription', (t) => {
    t.deepEqual(JSON.parse(getSubscribeInfoResponse()), {
        expireStatus: '0',
        isMqtt: false,
        remainDays: '30',
        subscriptionStatus: '1',
    });
});

test('getNoaLearnInfoResponse spoofs NOA learning as enabled', (t) => {
    t.is(getNoaLearnInfoResponse(), '1');
});
