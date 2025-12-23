import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './ADAS-activation-log.js';
import { runAgent } from '../lib/utils.js';

const logger = new Logger('ADAS-activation-mod');

let BaiduProviderUtil = null;

function doQuerySubscribeInfoHook() {
    try {
        BaiduProviderUtil.doQuerySubscribeInfo.implementation = function (/* unused */) {
            return '{"expireStatus":"0","isMqtt":false,"remainDays":"30","subscriptionStatus":"1"}';
        };
    } catch (e) {
        logger.error(`${ERROR.SUBSCRIBE_INFO} ${e.message}`);
        logger.error(e.stack);
    }
}

function doQueryNOALearnInfoHook() {
    try {
        BaiduProviderUtil.doQueryNOALearnInfo.implementation = function (/* unused */) {
            return '1';
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

function main() {
    logger.info(INFO.STARTING);

    init();

    doQuerySubscribeInfoHook();
    doQueryNOALearnInfoHook();
    logger.info(INFO.STARTED);
}

runAgent(main);
