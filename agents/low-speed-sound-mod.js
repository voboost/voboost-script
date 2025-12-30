import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './low-speed-sound-log.js';
import { runAgent, getFieldValue } from '../lib/utils.js';

const logger = new Logger('low-speed-sound-mod');

const LOW_SPEED_SOUND_DISABLE = 1;
const VEHICLE_STATE_INVALID = -1;

function disableLowSpeedSound() {
    const CanBusManager = Java.use('com.qinggan.canbus.CanBusManager');
    const VehicleState = Java.use('com.qinggan.canbus.VehicleState');

    const attemptsMax = 10;
    const delay = 800;
    let attempts = 0;

    const activate = () => {
        attempts++;

        if (attempts > attemptsMax) {
            return;
        }

        let result = VEHICLE_STATE_INVALID;

        try {
            const canBusManager = CanBusManager.getInstance();

            if (canBusManager === null) {
                setTimeout(() => activate(), delay);
            }

            const currentState = canBusManager.getVehicleState(
                getFieldValue(VehicleState, 'HUM_VSP_FUNCTION_SW')
            );

            if (currentState !== LOW_SPEED_SOUND_DISABLE) {
                result = canBusManager.setVehicleState(
                    getFieldValue(VehicleState, 'HUM_VSP_FUNCTION_SW'),
                    LOW_SPEED_SOUND_DISABLE
                );
            } else {
                return;
            }
        } catch (e) {
            logger.error(`${ERROR.DISABLE} ${e.message}`);
            logger.error(e.stack);
        }

        if (result === VEHICLE_STATE_INVALID) {
            setTimeout(() => activate(), delay);
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
