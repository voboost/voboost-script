import test from 'ava';
import {
    determineSoundAction,
    LOW_SPEED_SOUND_DISABLE,
    VEHICLE_STATE_INVALID,
    MAX_RETRY_ATTEMPTS,
    RETRY_DELAY_MS,
} from '../agents/low-speed-sound-mod.js';

// === Constants Tests ===
test('LOW_SPEED_SOUND_DISABLE constant is defined correctly', (t) => {
    t.is(LOW_SPEED_SOUND_DISABLE, 1);
});

test('VEHICLE_STATE_INVALID constant is defined correctly', (t) => {
    t.is(VEHICLE_STATE_INVALID, -1);
});

test('MAX_RETRY_ATTEMPTS constant is defined correctly', (t) => {
    t.is(MAX_RETRY_ATTEMPTS, 10);
});

test('RETRY_DELAY_MS constant is defined correctly', (t) => {
    t.is(RETRY_DELAY_MS, 800);
});

// === determineSoundAction - Max Attempts Tests ===
test('determineSoundAction stops when max attempts exceeded', (t) => {
    const result = determineSoundAction(
        0,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        11,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'max_attempts_reached');
});

test('determineSoundAction continues when attempts at max (not exceeded)', (t) => {
    const result = determineSoundAction(
        null,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        MAX_RETRY_ATTEMPTS,
        MAX_RETRY_ATTEMPTS,
        false
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'manager_unavailable');
});

test('determineSoundAction continues when attempts below max', (t) => {
    const result = determineSoundAction(
        null,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        5,
        MAX_RETRY_ATTEMPTS,
        false
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'manager_unavailable');
});

// === determineSoundAction - Manager Unavailable Tests ===
test('determineSoundAction retries when manager is unavailable', (t) => {
    const result = determineSoundAction(
        null,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS,
        false
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'manager_unavailable');
});

// === determineSoundAction - Vehicle State Unavailable Tests ===
test('determineSoundAction retries when manager is available but vehicle state is null', (t) => {
    const result = determineSoundAction(
        null,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
        // managerAvailable defaults to true
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'vehicle_state_unavailable');
});

test('determineSoundAction distinguishes vehicle_state_unavailable from manager_unavailable', (t) => {
    const managerUnavailable = determineSoundAction(
        null,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS,
        false
    );
    const vehicleStateUnavailable = determineSoundAction(
        null,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS,
        true
    );
    t.is(managerUnavailable.reason, 'manager_unavailable');
    t.is(vehicleStateUnavailable.reason, 'vehicle_state_unavailable');
    t.not(managerUnavailable.reason, vehicleStateUnavailable.reason);
});

// === determineSoundAction - Already in Target State Tests ===
test('determineSoundAction stops when already in target state', (t) => {
    const result = determineSoundAction(
        LOW_SPEED_SOUND_DISABLE,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'already_in_target_state');
});

test('determineSoundAction stops when current state equals target state (1)', (t) => {
    const result = determineSoundAction(1, 1, VEHICLE_STATE_INVALID, 3, MAX_RETRY_ATTEMPTS);
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'already_in_target_state');
});

// === determineSoundAction - Operation Failed Tests ===
test('determineSoundAction retries when operation result is VEHICLE_STATE_INVALID', (t) => {
    const result = determineSoundAction(
        0,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

test('determineSoundAction retries when operation result is -1', (t) => {
    const result = determineSoundAction(0, LOW_SPEED_SOUND_DISABLE, -1, 2, MAX_RETRY_ATTEMPTS);
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

test('determineSoundAction retries when operation fails multiple times', (t) => {
    const result = determineSoundAction(
        0,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        5,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

// === determineSoundAction - Operation Succeeded Tests ===
test('determineSoundAction stops when operation succeeds', (t) => {
    const result = determineSoundAction(0, LOW_SPEED_SOUND_DISABLE, 0, 1, MAX_RETRY_ATTEMPTS);
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'operation_succeeded');
});

test('determineSoundAction stops when operation result is 0 (success)', (t) => {
    const result = determineSoundAction(0, LOW_SPEED_SOUND_DISABLE, 0, 3, MAX_RETRY_ATTEMPTS);
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'operation_succeeded');
});

test('determineSoundAction stops when operation result is positive', (t) => {
    const result = determineSoundAction(0, LOW_SPEED_SOUND_DISABLE, 1, 2, MAX_RETRY_ATTEMPTS);
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'operation_succeeded');
});

test('determineSoundAction stops when operation succeeds with result 5', (t) => {
    const result = determineSoundAction(0, LOW_SPEED_SOUND_DISABLE, 5, 1, MAX_RETRY_ATTEMPTS);
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'operation_succeeded');
});

// === determineSoundAction - Different State Values Tests ===
test('determineSoundAction retries when current state is 2 and target is 1', (t) => {
    const result = determineSoundAction(
        2,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

test('determineSoundAction retries when current state is 3 and target is 1', (t) => {
    const result = determineSoundAction(
        3,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

test('determineSoundAction retries when current state is 5 and target is 1', (t) => {
    const result = determineSoundAction(
        5,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

// === determineSoundAction - Boundary Conditions Tests ===
test('determineSoundAction handles attempt count at max', (t) => {
    const result = determineSoundAction(
        0,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        MAX_RETRY_ATTEMPTS,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

test('determineSoundAction handles attempt count just below max', (t) => {
    const result = determineSoundAction(
        0,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        MAX_RETRY_ATTEMPTS - 1,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

test('determineSoundAction handles custom max attempts', (t) => {
    const result = determineSoundAction(0, LOW_SPEED_SOUND_DISABLE, VEHICLE_STATE_INVALID, 6, 5);
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'max_attempts_reached');
});

// === determineSoundAction - Edge Cases Tests ===
test('determineSoundAction handles undefined currentState as null', (t) => {
    const result = determineSoundAction(
        undefined,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    // undefined is not strictly null, so it will be treated as a state value
    // Since undefined !== LOW_SPEED_SOUND_DISABLE and result is VEHICLE_STATE_INVALID
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

test('determineSoundAction handles negative current state', (t) => {
    const result = determineSoundAction(
        -1,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

test('determineSoundAction handles large current state value', (t) => {
    const result = determineSoundAction(
        999,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

test('determineSoundAction handles zero attempt count', (t) => {
    const result = determineSoundAction(
        0,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        0,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

test('determineSoundAction handles negative attempt count', (t) => {
    const result = determineSoundAction(
        0,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        -1,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

// === determineSoundAction - Priority Order Tests ===
test('determineSoundAction prioritizes max attempts over manager unavailable', (t) => {
    const result = determineSoundAction(
        null,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        11,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'max_attempts_reached');
});

test('determineSoundAction prioritizes max attempts over already in target state', (t) => {
    const result = determineSoundAction(
        LOW_SPEED_SOUND_DISABLE,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        11,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'max_attempts_reached');
});

test('determineSoundAction prioritizes manager unavailable over already in target state', (t) => {
    // When currentState is null, we can't know if we're in target state
    const result = determineSoundAction(
        null,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS,
        false
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'manager_unavailable');
});

test('determineSoundAction prioritizes already in target state over operation failed', (t) => {
    const result = determineSoundAction(
        LOW_SPEED_SOUND_DISABLE,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'already_in_target_state');
});

// === determineSoundAction - Complex Scenarios Tests ===
test('determineSoundAction handles multiple failed attempts scenario', (t) => {
    // Simulate 9th attempt with failure
    const result = determineSoundAction(
        0,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        9,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, true);
    t.is(result.shouldStop, false);
    t.is(result.reason, 'operation_failed');
});

test('determineSoundAction handles final attempt with success', (t) => {
    // 10th attempt (max) with success - should stop
    const result = determineSoundAction(
        0,
        LOW_SPEED_SOUND_DISABLE,
        0,
        MAX_RETRY_ATTEMPTS,
        MAX_RETRY_ATTEMPTS
    );
    t.is(result.shouldRetry, false);
    t.is(result.shouldStop, true);
    t.is(result.reason, 'operation_succeeded');
});

// === determineSoundAction - Return Object Structure Tests ===
test('determineSoundAction always returns object with shouldRetry property', (t) => {
    const result = determineSoundAction(
        0,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    t.true(Object.prototype.hasOwnProperty.call(result, 'shouldRetry'));
    t.is(typeof result.shouldRetry, 'boolean');
});

test('determineSoundAction always returns object with shouldStop property', (t) => {
    const result = determineSoundAction(
        0,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    t.true(Object.prototype.hasOwnProperty.call(result, 'shouldStop'));
    t.is(typeof result.shouldStop, 'boolean');
});

test('determineSoundAction always returns object with reason property', (t) => {
    const result = determineSoundAction(
        0,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    t.true(Object.prototype.hasOwnProperty.call(result, 'reason'));
    t.is(typeof result.reason, 'string');
});

test('determineSoundAction returns mutually exclusive shouldRetry and shouldStop', (t) => {
    const result1 = determineSoundAction(
        0,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    t.not(result1.shouldRetry, result1.shouldStop);

    const result2 = determineSoundAction(
        LOW_SPEED_SOUND_DISABLE,
        LOW_SPEED_SOUND_DISABLE,
        VEHICLE_STATE_INVALID,
        1,
        MAX_RETRY_ATTEMPTS
    );
    t.not(result2.shouldRetry, result2.shouldStop);
});
