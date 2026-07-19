import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './forced-ev-log.js';
import { runAgent, getFieldValue } from '../lib/utils.js';

const logger = new Logger('forced-ev-mod');

// Manifest metadata consumed by the manifest generator. `process` is the
// Android process the daemon injects this agent into (hooks
// `com.qinggan.canbus.CanBusManager` in `com.qinggan.systemservice`);
// `boot:false` = inject as soon as the target is reachable.
export const AGENT_META = {
    id: 'forced-ev',
    process: 'com.qinggan.systemservice',
    boot: false,
};

export const FORCED_EV_ON = 5;
export const VEHICLE_STATE_INVALID = -1;
export const MAX_RETRY_ATTEMPTS = 10;
export const RETRY_DELAY_MS = 800;

/**
 * Determines the action to take for EV activation based on current state and attempt count.
 *
 * @param {number|null} currentState - Current vehicle EV state, or null if unavailable
 * @param {number} targetState - Target EV state to achieve (caller-supplied; in this module
 *   it is always the module-level FORCED_EV_ON constant)
 * @param {number} operationResult - Result of the set operation. Must be the module-level
 *   VEHICLE_STATE_INVALID sentinel when the operation has not run yet or failed - only pass
 *   the real operation result once it is known, otherwise this reason is meaningless.
 * @param {number} attemptCount - Current attempt number
 * @param {number} maxAttempts - Maximum number of attempts allowed
 * @returns {{shouldRetry: boolean, shouldStop: boolean, reason: string}} Decision object
 */
export function determineEvAction(
    currentState,
    targetState,
    operationResult,
    attemptCount,
    maxAttempts
) {
    // Check if max attempts reached
    if (attemptCount > maxAttempts) {
        return {
            shouldRetry: false,
            shouldStop: true,
            reason: 'max_attempts_reached',
        };
    }

    // Check if current state is null (canBusManager unavailable)
    if (currentState === null) {
        return {
            shouldRetry: true,
            shouldStop: false,
            reason: 'manager_unavailable',
        };
    }

    // Check if already in target state
    if (currentState === targetState) {
        return {
            shouldRetry: false,
            shouldStop: true,
            reason: 'already_in_target_state',
        };
    }

    // Check if operation failed
    if (operationResult === VEHICLE_STATE_INVALID) {
        return {
            shouldRetry: true,
            shouldStop: false,
            reason: 'operation_failed',
        };
    }

    // Operation succeeded
    return {
        shouldRetry: false,
        shouldStop: true,
        reason: 'operation_succeeded',
    };
}

export function activeForcedEv() {
    const CanBusManager = Java.use('com.qinggan.canbus.CanBusManager');
    const VehicleState = Java.use('com.qinggan.canbus.VehicleState');

    let attempts = 0;

    const activate = () => {
        attempts++;

        // currentState/result stay at their "unknown"/sentinel defaults whenever the
        // CAN-bus manager is unavailable, or when the target state is already reached
        // and the write operation is skipped below.
        let currentState = null;
        let result = VEHICLE_STATE_INVALID;

        try {
            const canBusManager = CanBusManager.getInstance();

            if (canBusManager !== null) {
                const iviSocModeSet = getFieldValue(VehicleState, 'IVI_SOC_MODESET');
                currentState = canBusManager.getVehicleState(iviSocModeSet);

                // Only attempt the CAN-bus write when not already at the target state.
                // determineEvAction still owns the "already in target state" decision
                // below, since it checks currentState/targetState before ever looking
                // at operationResult.
                if (currentState !== FORCED_EV_ON) {
                    result = canBusManager.setVehicleState(iviSocModeSet, FORCED_EV_ON);
                }
            }
        } catch (e) {
            logger.error(`${ERROR.ACTIVATION} ${e.message}`);
            logger.error(e.stack);
        }

        // Single decision point, evaluated exactly once per attempt, after the real
        // operation result (if any) is known. All branching below is driven purely by
        // decision.shouldStop/decision.shouldRetry - never by comparing decision.reason.
        const decision = determineEvAction(
            currentState,
            FORCED_EV_ON,
            result,
            attempts,
            MAX_RETRY_ATTEMPTS
        );

        if (decision.shouldStop) {
            return;
        }

        if (decision.shouldRetry) {
            setTimeout(() => activate(), RETRY_DELAY_MS);
        }
    };

    activate();
}

export function main() {
    logger.info(INFO.STARTING);

    activeForcedEv();

    logger.info(INFO.STARTED);
}

runAgent(main);
