import { Logger } from '../lib/logger.js';
import { LOG } from './ADAS-activation-log.js';
import { runAgent } from '../lib/utils.js';

const logger = new Logger('ADAS-activation-mod');

let BaiduProviderUtil = null;

function doQuerySubscribeInfoHook() {
    try {
        BaiduProviderUtil.doQuerySubscribeInfo.implementation = function (/* unused */) {
            return '{"expireStatus":"0","isMqtt":false,"remainDays":"30","subscriptionStatus":"1"}';
        };
    } catch (e) {
        logger.error(`${LOG.ERROR_SUBSCRIBE_INFO} ${e.message}`);
        logger.error(e.stack);
    }
}

function doQueryNOALearnInfoHook() {
    try {
        BaiduProviderUtil.doQueryNOALearnInfo.implementation = function (/* unused */) {
            return '1';
        };
    } catch (e) {
        logger.error(`${LOG.ERROR_NOA_LEARN_INFO} ${e.message}`);
        logger.error(e.stack);
    }
}

function init() {
    BaiduProviderUtil = Java.use(
        'com.qinggan.app.vehiclesetting.fragments.driveassistance.adas.BaiduProviderUtil'
    );
}

function main() {
    init();

    doQuerySubscribeInfoHook();
    doQueryNOALearnInfoHook();

    logger.info(LOG.HOOKS_INSTALLED);
}

runAgent(main);
