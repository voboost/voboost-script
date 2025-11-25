const APP_VIEWPORT_CONFIG_PATH = "/data/local/tmp/test/apps_viewport_config.json";
function LoadTextFile(file) {
    const FileInputStream = Java.use("java.io.FileInputStream");
    const InputStreamReader = Java.use("java.io.InputStreamReader");
    const BufferedReader = Java.use("java.io.BufferedReader");

    const fis = FileInputStream.$new(file);
    const isr = InputStreamReader.$new(fis);
    const reader = BufferedReader.$new(isr);
    let line, content = "";
    while ((line = reader.readLine()) !== null) {
        content += line + "\n";
    }
    reader.close();
    return content;
}
function parseConfig(content) {
    try {
        const config = JSON.parse(content);
        console.log("[+] Конфиг успешно загружен");
        return config;
    } catch (e) {
        console.error("[-] Ошибка загрузки конфига:", e.message);
        return null;
    }
}

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