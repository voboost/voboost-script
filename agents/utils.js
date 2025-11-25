const LANGUAGE_CONFIG_PATH = "/data/local/tmp/test/language-config.json";
const PHONE_NUM_CONFIG_PATH = "/data/local/tmp/test/phone-num-config.json";
const APP_CONFIG_PATH = "/data/local/tmp/test/apps-config.json";
const WEATHER_CONFIG_PATH = "/data/local/tmp/test/weather-config.json";
const APP_VIEWPORT_CONFIG_PATH = "/data/local/tmp/test/apps-viewport-config.json";

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

function parseAppConfig(content) {
    try {
        const Base64 = Java.use("android.util.Base64");
        const BitmapFactory = Java.use("android.graphics.BitmapFactory");

        console.log("[*] Загрузка конфига: " + APP_CONFIG_PATH);

        //const content = LoadTextFile(APP_CONFIG_PATH);
        const config = JSON.parse(content);

        const items = config.apps.map(obj => {
            const item = {
                package: obj.package,
                name: obj.name || ["", ""],
                icon_big: null,
                icon_small: null,
                replace_bar: obj.replace_bar || false,
                original_package: obj.original_package || [],
                package_sub_type: obj.package_sub_type || "UNDEFINED",
            };

            if (obj.icon_big && obj.icon_big != "") {
                try {
                    const bytes = Base64.decode(obj.icon_big, Base64.DEFAULT.value);
                    item.icon_big = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
                    console.log("[+] Иконка загружена для: " + obj.package);
                } catch (e) {
                    console.log("[-] Ошибка декодирования иконки для " + obj.package);
                }
            }
            if (obj.icon_small && obj.icon_small != "") {
                try {
                    const bytes = Base64.decode(obj.icon_small, Base64.DEFAULT.value);
                    item.icon_small = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
                    console.log("[+] Иконка загружена для: " + obj.package);
                } catch (e) {
                    console.log("[-] Ошибка декодирования иконки для " + obj.package);
                }
            }
            else {
                item.icon_small = item.icon_big;
            }

            return item;
        });

        console.log("[+] Конфиг загружен. Найдено " + items.length + " записей.");
        return { apps: items };

    } catch (e) {
        console.log("[-] Ошибка загрузки конфига: " + e.message);
        return null;
    }
}



