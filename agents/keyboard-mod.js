
let InputModeSwitcher = null;
let R_drawable = null;
let RUSSIAN_ICON = null;

let currentLayout = 'en'; // 'en' или 'ru'
let isShiftPressed = false;

const qwertyToJcuken = {
    'q': 'й', 'w': 'ц', 'e': 'у', 'r': 'к', 't': 'е', 'y': 'н', 'u': 'г',
    'i': 'ш', 'o': 'щ', 'p': 'з', '[': 'х', ']': 'ъ', '\\': 'ё',
    'a': 'ф', 's': 'ы', 'd': 'в', 'f': 'а', 'g': 'п', 'h': 'р', 'j': 'о',
    'k': 'л', 'l': 'д', ';': 'ж', "'": 'э', '`': 'ё',
    'z': 'я', 'x': 'ч', 'c': 'с', 'v': 'м', 'b': 'и', 'n': 'т', 'm': 'ь',
    ',': 'б', '.': 'ю', '/': '.'
};

function forceRerenderKeyboard() {
    // Получаем текущую клавиатуру через InputModeSwitcher
    const instance = InputModeSwitcher.getInstance();
    const imService = instance.mImeService.value;

    // Принудительно обновляем UI клавиатуры
    if (imService && imService.updateSoftKeyboard) {
        console.log("[Frida] Принудительное обновление клавиатуры");
        imService.updateSoftKeyboard();
    } else {
        console.log("[Frida] updateSoftKeyboard не найден, пробуем альтернативу");
        // Альтернативный метод: перезагрузка раскладки
        if (imService && imService.onConfigurationChanged) {
            const Configuration = Java.use('android.content.res.Configuration');
            const config = Configuration.$new();
            config.locale.value = Java.use('java.util.Locale').US.value;
            imService.onConfigurationChanged(config);
        }
    }
}


function switchModeForUserKeyHook() {
    const QGToast = Java.use('com.pateo.material.dialog.QGToast');

    InputModeSwitcher.switchModeForUserKey.implementation = function (i, z) {

        if (i === -2) { // Клавиша переключения языка
            currentLayout = (currentLayout === 'en') ? 'ru' : 'en';
            this.mInputIcon.value = (currentLayout === 'ru') ? RUSSIAN_ICON : R_drawable.ime_en.value;

            forceRerenderKeyboard();
            console.log(`[Frida] Раскладка изменена: ${currentLayout} (UI обновлён)`);

            this.saveInputMode(InputModeSwitcher.MODE_SKB_ENGLISH_LOWER.value); // Принудительно EN
            return this.mInputIcon.value; // НЕ вызываем оригинальный метод!
        }

        if (i === -1) { // Shift
            isShiftPressed = !isShiftPressed;
        }

        if (i === -10 && currentLayout === 'ru') {
            // Для русского режима блокируем голосовой ввод
            QGToast.makeText.overload('android.content.Context', 'java.lang.CharSequence', 'int')
                .call(QGToast, this.mImeService.value, "Голосовой ввод недоступен для русского языка", 3000).show();
            return this.mInputIcon.value;
        }

        return this.switchModeForUserKey.call(this, i, z);
    };
}

function addSoftKeyHook() {
    const SoftKeyboard = Java.use('com.qinggan.app.qgime.SoftKeyboard');
    SoftKeyboard.addSoftKey.implementation = function (softKey) {
        if (currentLayout === 'ru') {
            const keyCode = softKey.mKeyCode.value;
            if (keyCode >= 29 && keyCode <= 54) {
                const enChar = String.fromCharCode(97 + (keyCode - 29)).toLowerCase();
                const ruChar = qwertyToJcuken[enChar] || enChar;
                const finalChar = isShiftPressed ? ruChar.toUpperCase() : ruChar.toLowerCase();

                softKey.mLabel.value = Java.use('java.lang.String').$new(finalChar);
                softKey.mPopupLabel.value = Java.use('java.lang.String').$new(enChar.toUpperCase());
            }
        }
        return this.addSoftKey.call(this, softKey);
    };
}

function processKeyHook() {
    const EnglishInputProcessor = Java.use('com.qinggan.app.qgime.EnglishInputProcessor');
    EnglishInputProcessor.processKey.implementation = function (ic, event, isShift, commit) {
        if (!ic || !event) return this.processKey(ic, event, isShift, commit);

        const keyCode = event.getKeyCode();

        if (currentLayout === 'ru' && keyCode >= 29 && keyCode <= 54) {
            const enChar = String.fromCharCode(97 + (keyCode - 29)).toLowerCase();
            const ruChar = qwertyToJcuken[enChar] || enChar;
            const finalChar = isShiftPressed ? ruChar.toUpperCase() : ruChar.toLowerCase();

            if (commit) {
                ic.commitText(Java.use('java.lang.String').$new(finalChar), 1);
            }
            this.mLastKeyCode.value = keyCode;
            return true;
        }

        return this.processKey(ic, event, isShift, commit);
    };
}

function Init() {
    InputModeSwitcher = Java.use('com.qinggan.app.qgime.InputModeSwitcher');
    R_drawable = Java.use('com.qinggan.app.qgime.R$drawable');
    RUSSIAN_ICON = R_drawable.ime_pinyin.value; // Или R_drawable.cn.value

    console.log("[Frida] Инициализация завершена. RU_ICON: 0x" + RUSSIAN_ICON.toString(16));
}

function saveInputModeHook() {
    InputModeSwitcher.saveInputMode.implementation = function (mode) {
        const enMode = InputModeSwitcher.MODE_SKB_ENGLISH_LOWER.value;
        if (mode !== enMode) {
            console.log(`[Frida] БЛОКИРОВКА смены режима: 0x${mode.toString(16)} -> принудительно EN`);
            mode = enMode; // ВСЕГДА возвращаем английский режим
        }
        return this.saveInputMode.call(this, mode);
    };
}


function main() {
    Init();
    switchModeForUserKeyHook();
    addSoftKeyHook();
    processKeyHook();
    saveInputModeHook();

    const instance = InputModeSwitcher.getInstance();
    instance.saveInputMode(InputModeSwitcher.MODE_SKB_ENGLISH_LOWER.value);
    instance.mInputIcon.value = R_drawable.ime_en.value;
    currentLayout = 'en';

    console.log("[Frida] Скрипт загружен! Виртуальная русская раскладка активна.");
}

Java.perform(() => { main(); });