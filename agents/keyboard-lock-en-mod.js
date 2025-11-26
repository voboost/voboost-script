
function disableVoice() {
    
    const QGInputConfig = Java.use("com.qinggan.app.qgime.QGInputConfig");
    QGInputConfig.DISABLE_VOICE.value = true;
    console.log(`voice disable: ${QGInputConfig.DISABLE_VOICE.value}`);
}

function saveInputModeHook() {

    const InputModeSwitcher = Java.use("com.qinggan.app.qgime.InputModeSwitcher");

    const enModeLover = InputModeSwitcher.MODE_SKB_ENGLISH_LOWER.value;
    const enModeUpper = InputModeSwitcher.MODE_SKB_ENGLISH_UPPER.value;
    const enModeFirst = InputModeSwitcher.MODE_SKB_ENGLISH_FIRST.value;
    const enModeHkb = InputModeSwitcher.MODE_HKB_ENGLISH.value;
    const enModeSymbol1 = InputModeSwitcher.MODE_SKB_SYMBOL1_EN.value;
    const enModeSymbol2 = InputModeSwitcher.MODE_SKB_SYMBOL2_EN.value;

    InputModeSwitcher.saveInputMode.implementation = function (mode) {

        if (mode !== enModeLover &&
            mode !== enModeUpper &&
            mode !== enModeFirst &&
            mode !== enModeHkb &&
            mode !== enModeSymbol1 &&
            mode !== enModeSymbol2) {

            mode = enModeFirst;
        }

        return this.saveInputMode.call(this, mode);
    };
}

function main() {

    saveInputModeHook();
    disableVoice();
}

Java.perform(function () { main(); });
