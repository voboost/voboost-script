import {
    LANGUAGE_CONFIG_PATH,
    LoadTextFile,
    parseConfig
} from './utils.js';

let ActivityAnimUtils = null;

const APP_NAME = "ru.yandex.music";//"com.yourpackage.YourSettingsActivity";

let languageConfig = null;
let CustomOnClickListener = null;

const appNameLocalization = {
    EN: "Voboost",
    RU: "Voboost"
};

function getAppNameLocalization() {
    let currentLang = "EN";
    let appName = appNameLocalization.EN;

    if (languageConfig && languageConfig.language) {
        currentLang = languageConfig.language;
    }

    if (currentLang in appNameLocalization) {
        appName = appNameLocalization[currentLang];
    }

    return appName;
}

function startApp() {
    try {
        const ActivityThread = Java.use('android.app.ActivityThread');
        const PackageManager = ActivityThread.currentApplication().getPackageManager();
        const context = ActivityThread.currentApplication().getApplicationContext();
        const intent = PackageManager.getLaunchIntentForPackage(APP_NAME);
        intent.addFlags(0x10000000); // FLAG_ACTIVITY_NEW_TASK

        ActivityAnimUtils.startActivityByAnim
            .overload('android.content.Context', 'android.content.Intent')
            .call(ActivityAnimUtils, context, intent);

        console.log(`[+] Ваше приложение: ${APP_NAME}  успешно запущено!`);
    } catch (e) {
        console.log("[!] Ошибка при запуске приложения:", e.toString());
    }
}

function createMenuItem(content) {
    try {
        console.log("[+] Создание кастомной кнопки через копирование системных настроек");

        // Получаем контейнер LinearLayout внутри OverScrollView
        const menuContainer = content.carSettingBinding.value.menuContainer.value;
        const linearLayout = menuContainer.getChildAt(0);

        // Находим существующую кнопку системных настроек через binding
        const systemSettingsButton = content.carSettingBinding.value.mainMenuItemSystemSetting.value;
        if (!systemSettingsButton) {
            console.log("[!] Кнопка системных настроек не найдена");
            return;
        }

        // Копируем RelativeLayout для кнопки
        const RelativeLayout = Java.use('android.widget.RelativeLayout');
        const View = Java.use("android.view.View");

        const customButton = RelativeLayout.$new(content);
        customButton.setId(View.generateViewId());
        // Копируем параметры layout из образца
        const LinearLayout$LayoutParams = Java.use("android.widget.LinearLayout$LayoutParams");
        const sampleLayoutParams = systemSettingsButton.getLayoutParams();
        const layoutParams = LinearLayout$LayoutParams.$new.overload('android.widget.LinearLayout$LayoutParams')
            .call(LinearLayout$LayoutParams, sampleLayoutParams);

        customButton.setLayoutParams(layoutParams);

        // Копируем текстовый элемент
        const BoldTextView = Java.use('com.pateo.material.widgets.BoldTextView');
        const textView = Java.use("android.widget.TextView");
        const R_id = Java.use("com.qinggan.app.vehiclesetting.R$id");

        const sampleTextViewNative = systemSettingsButton.findViewById(R_id.main_menu_item_system_setting_textview.value);
        const buttonTextNamive = BoldTextView.$new(content);
        const buttonText = Java.cast(buttonTextNamive, textView);
        const sampleTextView = Java.cast(sampleTextViewNative, textView);

        // Копируем все параметры текста
        buttonText.setTextSize(0, sampleTextView.getTextSize());
        buttonText.setTextColor(sampleTextView.getTextColors());
        buttonText.setGravity(sampleTextView.getGravity());
        buttonText.setMaxWidth(sampleTextView.getMaxWidth());

        // Устанавливаем свой текст
        const JavaString = Java.use('java.lang.String');
        const appName = getAppNameLocalization();
        buttonText.setText(JavaString.$new(appName));

        const sampleTextLayoutParams = sampleTextView.getLayoutParams();
        // Копируем параметры layout для текста
        const RelativeLayout$LayoutParams = Java.use('android.widget.RelativeLayout$LayoutParams');
        const textLayoutParams = RelativeLayout$LayoutParams.$new.overload('android.widget.RelativeLayout$LayoutParams')
            .call(RelativeLayout$LayoutParams, sampleTextLayoutParams);

        buttonText.setLayoutParams(textLayoutParams);
        buttonText.setId(View.generateViewId());

        // Копируем иконку
        const ImageView = Java.use('android.widget.ImageView');
        const sampleIconN = systemSettingsButton.findViewById(R_id.main_menu_item_system_setting_imgview.value);
        const buttonIcon = ImageView.$new(content);

        const sampleIcon = Java.cast(sampleIconN, View);
        // Копируем фон иконки
        const sampleIconBackground = sampleIcon.getBackground();
        buttonIcon.setBackground(sampleIconBackground.getConstantState().newDrawable());

        const sampleIconLayoutParams = sampleIcon.getLayoutParams();
        // Копируем параметры layout для иконки
        const iconLayoutParams = RelativeLayout$LayoutParams.$new.overload('android.widget.RelativeLayout$LayoutParams')
            .call(RelativeLayout$LayoutParams, sampleIconLayoutParams);

        iconLayoutParams.addRule(1, buttonText.getId()); // RIGHT_OF buttonText
        buttonIcon.setLayoutParams(iconLayoutParams);

        // Добавляем элементы в RelativeLayout
        customButton.addView(buttonText);
        customButton.addView(buttonIcon);

        customButton.setOnClickListener(CustomOnClickListener.$new());

        // Добавляем кнопку перед системными настройками
        const systemSettingsId = R_id.main_menu_item_system_setting.value;
        let insertIndex = -1;

        const linearLayoutGroup = Java.cast(linearLayout, Java.use("android.view.ViewGroup"));

        for (let i = 0; i < linearLayoutGroup.getChildCount(); i++) {
            if (linearLayoutGroup.getChildAt(i).getId() === systemSettingsId) {
                insertIndex = i;
                break;
            }
        }

        if (insertIndex !== -1) {
            linearLayoutGroup.addView(customButton, insertIndex);
            console.log("[+] Кастомная кнопка добавлена перед системными настройками");
        } else {
            linearLayoutGroup.addView(customButton);
            console.log("[+] Кастомная кнопка добавлена в конец списка");
        }

    } catch (e) {
        console.log("[-] Ошибка при создании кастомной кнопки:", e.toString());
        console.log("[-] Stack trace:", e.stack);
    }
}

function onCreateHook() {
    const CarSettingActivity = Java.use("com.qinggan.app.vehiclesetting.CarSettingActivity");
    CarSettingActivity.onCreate.implementation = function (savedInstanceState) {
        // Выполняем оригинальный onCreate
        const result = this.onCreate.call(this, savedInstanceState);
        createMenuItem(this);
        return result;
    };
}

function init() {
    ActivityAnimUtils = Java.use("com.pateo.material.anim.ActivityAnimUtils");
    const View$OnClickListener = Java.use('android.view.View$OnClickListener');

    CustomOnClickListener = Java.registerClass({
        name: 'com.qinggan.frida.CustomClickListener',
        implements: [View$OnClickListener],
        methods: {
            onClick: function (view) { startApp(); }
        }
    });
}

function main() {
    // --- Основная логика Frida ---
    init();

    const languageContent = LoadTextFile(LANGUAGE_CONFIG_PATH);
    languageConfig = parseConfig(languageContent);

    onCreateHook();
    console.log("[+] Frida-скрипт успешно загружен для CarSettingActivity");
}

Java.perform(() => { main() });