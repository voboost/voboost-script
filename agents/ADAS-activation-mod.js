let BaiduProviderUtil = null;

function doQuerySubscribeInfoHook() {
    try {

        BaiduProviderUtil.doQuerySubscribeInfo.implementation = function (/* unused */) {
            return "{\"expireStatus\":\"0\",\"isMqtt\":false,\"remainDays\":\"30\",\"subscriptionStatus\":\"1\"}";
        };
    } catch (e) {
        console.log("[-] Error in doQuerySubscribeInfo: " + e.message);
        console.log(e.stack);
    }
}

function doQueryNOALearnInfoHook() {
    try {
        BaiduProviderUtil.doQueryNOALearnInfo.implementation = function (/* unused */) {
            return ""; //TODO: find out the answer format
        };
    } catch (e) {
        console.log("[-] Error in doQueryNOALearnInfo: " + e.message);
        console.log(e.stack);
    }
}

function init() {
    BaiduProviderUtil = Java.use("com.qinggan.app.vehiclesetting.fragments.driveassistance.adas.BaiduProviderUtil");
}

function main() {
    init();

    doQuerySubscribeInfoHook();
    doQueryNOALearnInfoHook();
}

Java.perform(() => { main(); });
