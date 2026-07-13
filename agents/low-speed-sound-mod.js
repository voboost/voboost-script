import { Logger } from '../lib/logger.js';
import { INFO, ERROR } from './low-speed-sound-log.js';
import { runAgent, getFieldValue } from '../lib/utils.js';

const logger = new Logger('low-speed-sound-mod');

export const LOW_SPEED_SOUND_DISABLE = 1;
export const VEHICLE_STATE_INVALID = -1;
export const MAX_RETRY_ATTEMPTS = 10;
export const RETRY_DELAY_MS = 800;

/**
 * Determines the action to take for low speed sound disabling based on current state and attempt count.
 *
 * NOTE ON CHECK ORDER: attempt-count, then manager availability, then vehicle-state availability,
 * then target-state match are all resolved *before* operationResult is ever consulted. Callers rely
 * on this ordering to safely pass a "not yet attempted" sentinel (VEHICLE_STATE_INVALID) as
 * operationResult when they only want to know whether to stop *before* performing the operation -
 * such a call can only ever resolve to 'operation_failed' (shouldRetry), never the false-positive
 * 'operation_succeeded'. Do not reorder the checks below without re-checking that call sites relying
 * on this stay correct.
 *
 * @param {number|null} currentState - Current vehicle low speed sound state, or null if unavailable
 * @param {number} targetState - Target sound state to achieve
 * @param {number} operationResult - Result of the set operation (VEHICLE_STATE_INVALID if failed or not yet attempted)
 * @param {number} attemptCount - Current attempt number
 * @param {number} maxAttempts - Maximum number of attempts allowed
 * @param {boolean} [managerAvailable=true] - Whether CanBusManager.getInstance() returned an instance
 * @returns {{shouldRetry: boolean, shouldStop: boolean, reason: string}} Decision object
 */
export function determineSoundAction(
    currentState,
    targetState,
    operationResult,
    attemptCount,
    maxAttempts,
    managerAvailable = true
) {
    // Check if max attempts reached
    if (attemptCount > maxAttempts) {
        return {
            shouldRetry: false,
            shouldStop: true,
            reason: 'max_attempts_reached',
        };
    }

    // Check if the CanBusManager instance itself is unavailable
    if (!managerAvailable) {
        return {
            shouldRetry: true,
            shouldStop: false,
            reason: 'manager_unavailable',
        };
    }

    // Manager is available, but reading the vehicle state failed/returned null
    if (currentState === null) {
        return {
            shouldRetry: true,
            shouldStop: false,
            reason: 'vehicle_state_unavailable',
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

function disableLowSpeedSound() {
    const CanBusManager = Java.use('com.qinggan.canbus.CanBusManager');
    const VehicleState = Java.use('com.qinggan.canbus.VehicleState');

    let attempts = 0;

    const activate = () => {
        attempts++;

        // Bail out before touching the CAN bus at all once the retry budget is spent, mirroring
        // the original early-exit behavior (avoids two wasted CAN-bus calls on the final attempt).
        if (attempts > MAX_RETRY_ATTEMPTS) {
            return;
        }

        let currentState = null;
        let managerAvailable = false;
        // Sentinel meaning "operation not yet attempted". Reusing VEHICLE_STATE_INVALID here (rather
        // than a separate magic number) is safe: per the ordering documented on determineSoundAction,
        // this value is only ever consulted after the manager/state/target checks above have already
        // decided not to stop, so it can only resolve to 'operation_failed', never 'operation_succeeded'.
        let result = VEHICLE_STATE_INVALID;

        try {
            const canBusManager = CanBusManager.getInstance();

            if (canBusManager === null) {
                const decision = determineSoundAction(
                    currentState,
                    LOW_SPEED_SOUND_DISABLE,
                    result,
                    attempts,
                    MAX_RETRY_ATTEMPTS,
                    managerAvailable
                );
                if (decision.shouldRetry) {
                    setTimeout(() => activate(), RETRY_DELAY_MS);
                }
                return;
            }

            managerAvailable = true;

            const humVspFunctionSw = getFieldValue(VehicleState, 'HUM_VSP_FUNCTION_SW');
            currentState = canBusManager.getVehicleState(humVspFunctionSw);

            const decision = determineSoundAction(
                currentState,
                LOW_SPEED_SOUND_DISABLE,
                result,
                attempts,
                MAX_RETRY_ATTEMPTS,
                managerAvailable
            );

            if (decision.shouldStop) {
                return;
            }

            // Attempt to set the state
            result = canBusManager.setVehicleState(humVspFunctionSw, LOW_SPEED_SOUND_DISABLE);
        } catch (e) {
            logger.error(`${ERROR.DISABLE} ${e.message}`);
            logger.error(e.stack);
        }

        // Check if we need to retry based on the operation result
        const finalDecision = determineSoundAction(
            currentState,
            LOW_SPEED_SOUND_DISABLE,
            result,
            attempts,
            MAX_RETRY_ATTEMPTS,
            managerAvailable
        );
        if (finalDecision.shouldRetry) {
            setTimeout(() => activate(), RETRY_DELAY_MS);
        }
    };

    activate();
}

function main() {
    logger.info(INFO.STARTING);

    disableLowSpeedSound();

    logger.info(INFO.STARTED);
}

runAgent(main);
