import {
    APP_VIEWPORT_CONFIG_PATH,
    LoadTextFile,
    parseConfig,
} from './utils.js';

let config = null;

function isWhiteListAppHook() {
    try {
        var MultiDisplayImpl = Java.use('com.qinggan.systemservice.multidisplay.MultiDisplayImpl');
        MultiDisplayImpl.isWhiteListApp.implementation = function (packageName) {

            console.log("[*] приложение мультиэкранное? " + packageName);
            for (let app of config.apps) {
                if (packageName !== app.package) continue;
                return app.screen.length > 1;
            }

            return this.isWhiteListApp.call(MultiDisplayImpl, packageName);
        };
    }
    catch (e) {
        console.error('[app_multi_display] Error in hook:', e.message);
        console.error(e.stack);
    }
}

function main() {

    const appViewPortContent = LoadTextFile(APP_VIEWPORT_CONFIG_PATH);
    config = parseConfig(appViewPortContent);
    isWhiteListAppHook();
}

Java.perform(function () { main(); });
