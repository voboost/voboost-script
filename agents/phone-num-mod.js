function getAmendNumber(number) {
    let result = number.toString().trim();
    // Если строка начинается с +86, убираем +86
    if (result.startsWith("+86")) {
        result = result.substring(3);
        return result;
    }
    return result;
}

function getAmendNumberHook() {
    try {
        const UtilClass = Java.use("com.qinggan.bluetoothphone.util.Util");
        UtilClass.getAmendNumber.implementation = function (str) {
            return getAmendNumber(str);
        };
        console.log("[*] Метод getAmendNumber в bluetoothphone успешно перехвачен и модифицирован.");
    } catch (e) {
        console.log("[!] Класс bluetoothphone.Util недоступен в этом процессе");
    }
}

function fixContactCacheInfos() {
    try {
        const PbapProfileManagerClass = Java.use("com.qinggan.bluetoothphone.logic.manager.PbapProfileManager");
        PbapProfileManagerClass.startSync.call(PbapProfileManagerClass);

    } catch (e) {
        console.log("[!] Ошибка при обработке кэша контактов:", e.message);
        console.log(e.stack);
    }
}

function main() {
    console.log("[*] Старт hok исправления телефонов");
    getAmendNumberHook();
    fixContactCacheInfos();
}

Java.perform(() => { main(); });
