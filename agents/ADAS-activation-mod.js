import { Logger } from '../lib/logger.js';

const logger = new Logger('ADAS-activation-mod');

let BaiduProviderUtil = null;

function doQuerySubscribeInfoHook() {
    try {
        BaiduProviderUtil.doQuerySubscribeInfo.implementation = function (/* unused */) {
            return '{"expireStatus":"0","isMqtt":false,"remainDays":"30","subscriptionStatus":"1"}';
        };
    } catch (e) {
        logger.error(`Error in doQuerySubscribeInfo: ${e.message}`);
        logger.error(e.stack);
    }
}

function doQueryNOALearnInfoHook() {
    try {
        BaiduProviderUtil.doQueryNOALearnInfo.implementation = function (/* unused */) {
            return '1';
        };
    } catch (e) {
        logger.error(`Error in doQueryNOALearnInfo: ${e.message}`);
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

    logger.info('ADAS activation hooks installed');
}

Java.perform(() => {
    main();
});
