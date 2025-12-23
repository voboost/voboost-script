import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './forced-ev-log.js';
import { runAgent } from '../lib/utils.js';

const logger = new Logger('forced-ev-mod');

const FORCED_EV_ON = 5;
const VEHICLE_STATE_INVALID = -1;

function activeForcedEv() {
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

            const currentState = canBusManager.getVehicleState(VehicleState.IVI_SOC_MODESET.value);

            if (currentState !== FORCED_EV_ON) {
                result = canBusManager.setVehicleState(
                    VehicleState.IVI_SOC_MODESET.value,
                    FORCED_EV_ON
                );
            } else {
                return;
            }
        } catch (e) {
            logger.error(`${ERROR.ACTIVATION} ${e.message}`);
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

    activeForcedEv();

    logger.debug(DEBUG.ACTIVATED);
    logger.info(INFO.STARTED);
}

runAgent(main);
