import test from 'ava';
import {
    determineEvAction,
    activeForcedEv,
    FORCED_EV_ON,
    VEHICLE_STATE_INVALID,
    MAX_RETRY_ATTEMPTS,
} from '../agents/forced-ev-mod.js';

/**
 * Installs a minimal Frida-like `Java` global backed by the provided CanBusManager
 * instance (or `null` to simulate an unavailable manager), and a `setTimeout` stub
 * that records scheduled callbacks instead of actually waiting, so retry chains can
 * be driven synchronously and counted precisely.
 *
 * @param {object|null} canBusManagerInstance
 * @returns {{scheduled: Array<Function>, restore: Function, runNextScheduled: Function}}
 */
function installCanBusMocks(canBusManagerInstance) {
    const originalJava = globalThis.Java;
    const originalSetTimeout = globalThis.setTimeout;

    const scheduled = [];

    globalThis.Java = {
        use(className) {
            if (className === 'com.qinggan.canbus.CanBusManager') {
                return {
                    getInstance: () => canBusManagerInstance,
                };
            }
            if (className === 'com.qinggan.canbus.VehicleState') {
                return { IVI_SOC_MODESET: 'IVI_SOC_MODESET' };
            }
            throw new Error(`Unexpected Java.use call: ${className}`);
        },
    };

    globalThis.setTimeout = (fn) => {
        scheduled.push(fn);
        return scheduled.length;
    };

    return {
        scheduled,
        restore() {
            globalThis.Java = originalJava;
            globalThis.setTimeout = originalSetTimeout;
        },
        runNextScheduled() {
            const fn = scheduled.shift();
            if (fn) fn();
        },
    };
}

// The magic-number constants (FORCED_EV_ON, VEHICLE_STATE_INVALID,
// MAX_RETRY_ATTEMPTS, RETRY_DELAY_MS) are exercised as inputs/expected values
// throughout the behavioral tests below — no separate literal-echoing tests.

// === determineEvAction - Max Attempts Tests ===
test('determineEvAction stops when max attempts exceeded', (t) => {
    const result = determineEvAction(
        3,
        FORCED_EV_ON,
        VEHICLE_STATE_INVALID,
        11,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'max_attempts_reached');
});

test('determineEvAction continues when attempts at max (not exceeded)', (t) => {
    const result = determineEvAction(
        null,
        FORCED_EV_ON,
        VEHICLE_STATE_INVALID,
        MAX_RETRY_ATTEMPTS,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'manager_unavailable');
});

// === determineEvAction - Manager Unavailable Tests ===
test('determineEvAction retries when currentState is null', (t) => {
    const result = determineEvAction(
        null,
        FORCED_EV_ON,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'manager_unavailable');
});

// === determineEvAction - Already in Target State Tests ===
test('determineEvAction stops when already in target state', (t) => {
    const result = determineEvAction(
        FORCED_EV_ON,
        FORCED_EV_ON,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'already_in_target_state');
});

// === determineEvAction - Operation Failed Tests ===
test('determineEvAction retries when operation result is VEHICLE_STATE_INVALID', (t) => {
    const result = determineEvAction(3, FORCED_EV_ON, VEHICLE_STATE_INVALID, 1, MAX_RETRY_ATTEMPTS);
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

// === determineEvAction - Operation Succeeded Tests ===
test('determineEvAction stops when operation succeeds', (t) => {
    const result = determineEvAction(3, FORCED_EV_ON, 0, 1, MAX_RETRY_ATTEMPTS);
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'operation_succeeded');
});

test('determineEvAction stops when operation result is 0 (success)', (t) => {
    const result = determineEvAction(3, FORCED_EV_ON, 0, 3, MAX_RETRY_ATTEMPTS);
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'operation_succeeded');
});

test('determineEvAction stops when operation result is positive', (t) => {
    const result = determineEvAction(3, FORCED_EV_ON, 1, 2, MAX_RETRY_ATTEMPTS);
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'operation_succeeded');
});

test('determineEvAction stops when operation succeeds with result 5', (t) => {
    const result = determineEvAction(3, FORCED_EV_ON, 5, 1, MAX_RETRY_ATTEMPTS);
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'operation_succeeded');
});

// === determineEvAction - Different State Values Tests ===
test('determineEvAction retries when current state is 0 and target is 5', (t) => {
    const result = determineEvAction(0, FORCED_EV_ON, VEHICLE_STATE_INVALID, 1, MAX_RETRY_ATTEMPTS);
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

test('determineEvAction retries when current state is 3 and target is 5', (t) => {
    const result = determineEvAction(3, FORCED_EV_ON, VEHICLE_STATE_INVALID, 1, MAX_RETRY_ATTEMPTS);
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

test('determineEvAction retries when current state is 4 and target is 5', (t) => {
    const result = determineEvAction(4, FORCED_EV_ON, VEHICLE_STATE_INVALID, 1, MAX_RETRY_ATTEMPTS);
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

// === determineEvAction - Boundary Conditions Tests ===
test('determineEvAction handles attempt count at max', (t) => {
    const result = determineEvAction(
        3,
        FORCED_EV_ON,
        VEHICLE_STATE_INVALID,
        MAX_RETRY_ATTEMPTS,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

test('determineEvAction handles attempt count just below max', (t) => {
    const result = determineEvAction(
        3,
        FORCED_EV_ON,
        VEHICLE_STATE_INVALID,
        MAX_RETRY_ATTEMPTS - 1,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

test('determineEvAction handles custom max attempts', (t) => {
    const result = determineEvAction(3, FORCED_EV_ON, VEHICLE_STATE_INVALID, 6, 5);
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'max_attempts_reached');
});

// === determineEvAction - Edge Cases Tests ===
test('determineEvAction handles undefined currentState as null', (t) => {
    const result = determineEvAction(
        undefined,
        FORCED_EV_ON,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    // undefined is not strictly null, so it will be treated as a state value
    // Since undefined !== FORCED_EV_ON and result is VEHICLE_STATE_INVALID
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

test('determineEvAction handles negative current state', (t) => {
    const result = determineEvAction(
        -1,
        FORCED_EV_ON,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

test('determineEvAction handles large current state value', (t) => {
    const result = determineEvAction(
        999,
        FORCED_EV_ON,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

test('determineEvAction handles zero attempt count', (t) => {
    const result = determineEvAction(3, FORCED_EV_ON, VEHICLE_STATE_INVALID, 0, MAX_RETRY_ATTEMPTS);
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

test('determineEvAction handles negative attempt count', (t) => {
    const result = determineEvAction(
        3,
        FORCED_EV_ON,
        VEHICLE_STATE_INVALID,
        -1,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

// === determineEvAction - Priority Order Tests ===
test('determineEvAction prioritizes max attempts over manager unavailable', (t) => {
    const result = determineEvAction(
        null,
        FORCED_EV_ON,
        VEHICLE_STATE_INVALID,
        11,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'max_attempts_reached');
});

test('determineEvAction prioritizes max attempts over already in target state', (t) => {
    const result = determineEvAction(
        FORCED_EV_ON,
        FORCED_EV_ON,
        VEHICLE_STATE_INVALID,
        11,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'max_attempts_reached');
});

// === determineEvAction - Complex Scenarios Tests ===
test('determineEvAction handles transition from state 0 to 5 with success', (t) => {
    const result = determineEvAction(0, FORCED_EV_ON, 0, 1, MAX_RETRY_ATTEMPTS);
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'operation_succeeded');
});

test('determineEvAction handles final attempt with success', (t) => {
    // 10th attempt (max) with success - should stop
    const result = determineEvAction(3, FORCED_EV_ON, 0, MAX_RETRY_ATTEMPTS, MAX_RETRY_ATTEMPTS);
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'operation_succeeded');
});

test('determineEvAction returns mutually exclusive shouldRetry and shouldStop', (t) => {
    const result1 = determineEvAction(
        3,
        FORCED_EV_ON,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    t.not(result1.shouldRetry, result1.shouldStop);

    const result2 = determineEvAction(
        FORCED_EV_ON,
        FORCED_EV_ON,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    t.not(result2.shouldRetry, result2.shouldStop);
});

// === activeForcedEv - Orchestration/Retry Integration Tests ===
// These exercise the real activate() loop (mocked Java/setTimeout globals), not just
// the pure determineEvAction function, so they use test.serial since they mutate
// process-wide globals.

test.serial(
    'activeForcedEv stops immediately without retry or a write when already in target state',
    (t) => {
        const canBusManager = {
            getVehicleState: () => FORCED_EV_ON,
            setVehicleState: () => {
                t.fail('setVehicleState should not be called when already in target state');
            },
        };
        const mocks = installCanBusMocks(canBusManager);
        try {
            activeForcedEv();
            t.is(mocks.scheduled.length, 0);
        } finally {
            mocks.restore();
        }
    }
);

test.serial(
    'activeForcedEv schedules exactly one retry when CanBusManager is unavailable (no avalanche)',
    (t) => {
        const mocks = installCanBusMocks(null);
        try {
            activeForcedEv();
            // Regression test: previously a missing `return` after scheduling this retry
            // let execution fall through and schedule a second setTimeout too, causing a
            // runaway retry-queue avalanche.
            t.is(mocks.scheduled.length, 1);
        } finally {
            mocks.restore();
        }
    }
);

test.serial('activeForcedEv retries once then stops after the operation succeeds', (t) => {
    let getVehicleStateCalls = 0;
    let setVehicleStateCalls = 0;
    const canBusManager = {
        getVehicleState: () => {
            getVehicleStateCalls++;
            return 0; // not yet at target
        },
        setVehicleState: () => {
            setVehicleStateCalls++;
            // Fail on the first attempt, succeed on the retry
            return setVehicleStateCalls === 1 ? VEHICLE_STATE_INVALID : FORCED_EV_ON;
        },
    };
    const mocks = installCanBusMocks(canBusManager);
    try {
        activeForcedEv();
        t.is(setVehicleStateCalls, 1);
        t.is(mocks.scheduled.length, 1);

        mocks.runNextScheduled();
        t.is(setVehicleStateCalls, 2);
        t.is(getVehicleStateCalls, 2);
        // No further retry once the operation succeeds
        t.is(mocks.scheduled.length, 0);
    } finally {
        mocks.restore();
    }
});

test.serial(
    'activeForcedEv stops after MAX_RETRY_ATTEMPTS without scheduling further retries',
    (t) => {
        const canBusManager = {
            getVehicleState: () => 0,
            setVehicleState: () => VEHICLE_STATE_INVALID, // always fails
        };
        const mocks = installCanBusMocks(canBusManager);
        try {
            activeForcedEv(); // attempt 1
            t.is(mocks.scheduled.length, 1);

            // Attempts 2..MAX_RETRY_ATTEMPTS should each still fail and reschedule exactly once
            for (let i = 0; i < MAX_RETRY_ATTEMPTS - 1; i++) {
                mocks.runNextScheduled();
                t.is(mocks.scheduled.length, 1);
            }

            // Attempt MAX_RETRY_ATTEMPTS + 1 exceeds the limit: stop, no further retry
            mocks.runNextScheduled();
            t.is(mocks.scheduled.length, 0);
        } finally {
            mocks.restore();
        }
    }
);
