import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './adas-activation-log.js';
import { runAgent } from '../lib/utils.js';

const logger = new Logger('adas-activation-mod');

// Manifest metadata consumed by the manifest generator. `process` is the
// Android process the daemon injects this agent into (owner of the hooked
// class); `boot:false` = inject as soon as the target is reachable (spawn
// gating handles earliest reach; no boot gate needed).
export const AGENT_META = {
    id: 'adas-activation',
    process: 'com.qinggan.app.vehiclesetting',
    boot: false,
};

let BaiduProviderUtil = null;

/**
 * Returns the JSON response string for subscription information query.
 * This response indicates an active subscription with 30 days remaining.
 *
 * The returned string, once parsed, has the following shape:
 *   - expireStatus {string} - Expiration status ("0" = not expired)
 *   - isMqtt {boolean} - MQTT connection status
 *   - remainDays {string} - Number of days remaining in subscription
 *   - subscriptionStatus {string} - Subscription status ("1" = active)
 *
 * @returns {string} JSON string containing subscription status information
 */
export function getSubscribeInfoResponse() {
    return '{"expireStatus":"0","isMqtt":false,"remainDays":"30","subscriptionStatus":"1"}';
}

/**
 * Returns the response string for NOA (Navigation on Autopilot) learn information query.
 * This response indicates that NOA learning is complete or enabled.
 *
 * @returns {string} NOA learn info status ("1" = learned/enabled)
 */
export function getNoaLearnInfoResponse() {
    return '1';
}

function doQuerySubscribeInfoHook() {
    try {
        BaiduProviderUtil.doQuerySubscribeInfo.implementation = function (/* unused */) {
            return getSubscribeInfoResponse();
        };
    } catch (e) {
        logger.error(`${ERROR.SUBSCRIBE_INFO} ${e.message}`);
        logger.error(e.stack);
    }
}

function doQueryNOALearnInfoHook() {
    try {
        BaiduProviderUtil.doQueryNOALearnInfo.implementation = function (/* unused */) {
            return getNoaLearnInfoResponse();
        };
    } catch (e) {
        logger.error(`${ERROR.NOA_LEARN_INFO} ${e.message}`);
        logger.error(e.stack);
    }
}

function init() {
    BaiduProviderUtil = Java.use(
        'com.qinggan.app.vehiclesetting.fragments.driveassistance.adas.BaiduProviderUtil'
    );
}

export function main() {
    logger.info(INFO.STARTING);

    init();
    doQuerySubscribeInfoHook();
    doQueryNOALearnInfoHook();

    logger.info(INFO.STARTED);
}

runAgent(main);
