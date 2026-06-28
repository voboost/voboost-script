import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './voboost-to-menu-log.js';

import {
    LANGUAGE_CONFIG_PATH,
    loadConfig,
    runAgent,
    registerClassSafe,
    getFieldValue,
    getRpcParams,
} from '../lib/utils.js';

const logger = new Logger('voboost-to-menu-mod');

let ActivityAnimUtils = null;

let activityClass = null;
let menuTitle = null;
let languageConfig = null;
let CustomOnClickListener = null;

const appNameLocalization = {
    EN: 'Voboost',
    RU: 'Voboost',
};

/**
 * Gets the localized app name based on the current language configuration.
 * Supports multiple locale formats (e.g., "ru", "ru_RU", "RU").
 * Falls back to English if the language is not found in the localization map.
 *
 * @param {string} [locale] - Optional locale string (e.g., "ru", "en", "eu").
 *                            If not provided, uses languageConfig.language.
 * @param {Object} [localizationMap] - Optional map of language code to localized
 *                            name. Defaults to this agent's own appNameLocalization
 *                            map. Exposed mainly so tests can exercise the
 *                            locale-parsing/branching logic with fixture data
 *                            whose EN/RU values genuinely differ.
 * @returns {string} Localized app name
 *
 * @example
 * getAppNameLocalization('ru'); // Returns 'Voboost'
 * getAppNameLocalization('en'); // Returns 'Voboost'
 * getAppNameLocalization(); // Uses languageConfig.language
 */
function getAppNameLocalization(locale, localizationMap = appNameLocalization) {
    let currentLang = 'EN';
    let localizedName = localizationMap.EN;

    // Use provided locale or fall back to languageConfig
    if (locale) {
        currentLang = locale;
    } else if (languageConfig && languageConfig.language) {
        currentLang = languageConfig.language;
    }

    // Normalize locale to uppercase and extract base language code
    const normalizedLang = currentLang.toString().toUpperCase().split('_')[0];

    if (normalizedLang in localizationMap) {
        localizedName = localizationMap[normalizedLang];
    }

    return localizedName;
}

/**
 * Launches the configured app using Android's ActivityAnimUtils.
 * Retrieves the launch intent for the app package and starts it with animation.
 *
 * @throws {Error} If app launch fails
 */
function startApp() {
    try {
        const ActivityThread = Java.use('android.app.ActivityThread');
        const context = ActivityThread.currentApplication().getApplicationContext();

        const Intent = Java.use('android.content.Intent');
        const ComponentName = Java.use('android.content.ComponentName');

        // activityClass is the fully-qualified target Activity class name
        // (e.g. "ru.voboost.MainActivity"). We build an explicit-component
        // Intent from plain strings rather than via Class.forName(activityClass):
        // this agent runs injected into a different app's process, whose
        // classloader does not (and cannot) have the target app's classes
        // loaded, so Class.forName would throw ClassNotFoundException.
        const packageName = activityClass.substring(0, activityClass.lastIndexOf('.'));

        const intent = Intent.$new();
        intent.setComponent(ComponentName.$new(packageName, activityClass));
        intent.addFlags(0x10000000); // FLAG_ACTIVITY_NEW_TASK

        ActivityAnimUtils.startActivityByAnim
            .overload('android.content.Context', 'android.content.Intent')
            .call(ActivityAnimUtils, context, intent);

        logger.info(`${INFO.APP_LAUNCHED} ${activityClass}`);
    } catch (e) {
        logger.error(`${ERROR.STARTING_APP} ${e.toString()}`);
    }
}

/**
 * Creates a custom menu item button in the car settings menu.
 * Clones the system settings button's layout and styling, then adds
 * a custom button with localized text and click handler.
 *
 * @param {Object} content - Android Context object for the activity
 * @throws {Error} If button creation fails
 */
function createMenuItem(content) {
    try {
        logger.debug(DEBUG.CREATING_BUTTON);

        const carSettingBinding = getFieldValue(content, 'carSettingBinding');

        // Get the LinearLayout container inside OverScrollView
        const menuContainer = getFieldValue(carSettingBinding, 'menuContainer');
        const linearLayout = menuContainer.getChildAt(0);

        // Find existing system settings button via binding
        const systemSettingsButton = getFieldValue(carSettingBinding, 'mainMenuItemSystemSetting');

        if (!systemSettingsButton) {
            logger.error(ERROR.SYSTEM_SETTINGS_NOT_FOUND);
            return;
        }

        const View = Java.use('android.view.View');
        const ViewGroup = Java.use('android.view.ViewGroup');
        const TextView = Java.use('android.widget.TextView');
        const ImageView = Java.use('android.widget.ImageView');
        const BoldTextView = Java.use('com.pateo.material.widgets.BoldTextView');
        const RelativeLayout = Java.use('android.widget.RelativeLayout');
        const LinearLayout$LayoutParams = Java.use('android.widget.LinearLayout$LayoutParams');

        const sourceButton = Java.cast(systemSettingsButton, ViewGroup);

        // Clone the container RelativeLayout with all layout params and padding
        const customButton = RelativeLayout.$new(content);
        customButton.setId(View.generateViewId());

        const srcLayoutParams = sourceButton.getLayoutParams();
        const layoutParams = LinearLayout$LayoutParams.$new
            .overload('android.widget.LinearLayout$LayoutParams')
            .call(LinearLayout$LayoutParams, srcLayoutParams);
        customButton.setLayoutParams(layoutParams);

        // Copy padding from source button
        customButton.setPadding(
            sourceButton.getPaddingLeft(),
            sourceButton.getPaddingTop(),
            sourceButton.getPaddingRight(),
            sourceButton.getPaddingBottom()
        );

        // Clone all children from the source button
        const RelativeLayout$LayoutParams = Java.use('android.widget.RelativeLayout$LayoutParams');
        const JavaString = Java.use('java.lang.String');
        const titleText = menuTitle || getAppNameLocalization();

        for (let i = 0; i < sourceButton.getChildCount(); i++) {
            const child = sourceButton.getChildAt(i);

            if (TextView.class.isInstance(child)) {
                // TextView or subclass (BoldTextView) — clone and set custom text
                const srcText = Java.cast(child, TextView);
                const srcLayoutParams = srcText.getLayoutParams();
                const textLayoutParams = RelativeLayout$LayoutParams.$new
                    .overload('android.widget.RelativeLayout$LayoutParams')
                    .call(RelativeLayout$LayoutParams, srcLayoutParams);

                const clonedTextNative = BoldTextView.$new(content);
                const clonedText = Java.cast(clonedTextNative, TextView);
                clonedText.setTextSize(0, srcText.getTextSize());
                clonedText.setTextColor(srcText.getTextColors());
                clonedText.setGravity(srcText.getGravity());
                if (srcText.getMaxWidth() > 0) {
                    clonedText.setMaxWidth(srcText.getMaxWidth());
                }
                clonedText.setText(JavaString.$new(titleText));
                clonedText.setLayoutParams(textLayoutParams);
                clonedText.setId(View.generateViewId());

                customButton.addView(clonedText);
            } else if (ImageView.class.isInstance(child)) {
                // ImageView — clone icon/arrow
                const srcImg = Java.cast(child, ImageView);
                const srcImgLayoutParams = srcImg.getLayoutParams();
                const imgLayoutParams = RelativeLayout$LayoutParams.$new
                    .overload('android.widget.RelativeLayout$LayoutParams')
                    .call(RelativeLayout$LayoutParams, srcImgLayoutParams);

                const clonedImg = ImageView.$new(content);

                // Copy background drawable
                const bg = srcImg.getBackground();
                if (bg) {
                    clonedImg.setBackground(bg.getConstantState().newDrawable());
                }

                // Copy image drawable
                const drawable = srcImg.getDrawable();
                if (drawable) {
                    clonedImg.setImageDrawable(drawable.getConstantState().newDrawable());
                }

                clonedImg.setLayoutParams(imgLayoutParams);
                clonedImg.setId(View.generateViewId());

                customButton.addView(clonedImg);
            }
        }

        customButton.setOnClickListener(CustomOnClickListener.$new());

        // Insert button before system settings in the LinearLayout
        const R_id = Java.use('com.qinggan.app.vehiclesetting.R$id');
        const systemSettingsId = getFieldValue(R_id, 'main_menu_item_system_setting');
        let insertIndex = -1;
        const linearLayoutGroup = Java.cast(linearLayout, ViewGroup);

        for (let i = 0; i < linearLayoutGroup.getChildCount(); i++) {
            if (linearLayoutGroup.getChildAt(i).getId() === systemSettingsId) {
                insertIndex = i;
                break;
            }
        }

        if (insertIndex !== -1) {
            linearLayoutGroup.addView(customButton, insertIndex);
        } else {
            linearLayoutGroup.addView(customButton);
        }

        logger.info(INFO.BUTTON_ADDED);
    } catch (e) {
        logger.error(`${ERROR.CREATING_BUTTON} ${e.toString()}`);
        logger.error(e.stack);
    }
}

/**
 * Hooks into CarSettingActivity's onCreate method to inject custom menu item.
 * Intercepts the activity creation and adds the custom button after the
 * original onCreate completes.
 */
function onCreateHook() {
    const CarSettingActivity = Java.use('com.qinggan.app.vehiclesetting.CarSettingActivity');
    CarSettingActivity.onCreate.implementation = function (savedInstanceState) {
        // Execute original onCreate
        const result = this.onCreate.call(this, savedInstanceState);
        createMenuItem(this);
        return result;
    };
}

/**
 * Initializes required Java classes and registers custom click listener.
 * Sets up ActivityAnimUtils and creates a custom OnClickListener implementation
 * that launches the app when the menu item is clicked.
 */
function init() {
    ActivityAnimUtils = Java.use('com.pateo.material.anim.ActivityAnimUtils');
    const View$OnClickListener = Java.use('android.view.View$OnClickListener');

    CustomOnClickListener = registerClassSafe(
        {
            name: 'com.qinggan.frida.CustomClickListener',
            implements: [View$OnClickListener],
            methods: {
                onClick: function () {
                    startApp();
                },
            },
        },
        'ru.voboost.stub.ClickListener',
        logger
    );
}

/**
 * Main entry point for the voboost-to-menu agent.
 * Initializes the agent, loads language configuration, and sets up hooks.
 */
function main() {
    logger.info(INFO.STARTING);

    // Read parameters from frida-inject --parameters. Apply the default target
    // activity unconditionally so activityClass is never left null (e.g. when
    // init() runs without parameters) — otherwise startApp() would throw on
    // activityClass.substring(...) when the menu item is clicked.
    const params = getRpcParams();
    activityClass = (params && params.activityClass) || 'ru.voboost.MainActivity';
    menuTitle = (params && params.menuTitle) || null;

    // Load language config using the standard, cross-agent pattern (loadConfig
    // itself checks params.config / params.configPath before falling back to
    // LANGUAGE_CONFIG_PATH). languageConfig ends up as the actual
    // {language: 'EN'|'RU'} object, never a raw string.
    languageConfig = loadConfig(LANGUAGE_CONFIG_PATH, logger);
    if (!languageConfig) {
        logger.debug(DEBUG.LANGUAGE_CONFIG_NOT_AVAILABLE);
    }

    init();
    onCreateHook();
    logger.info(INFO.STARTED);
}

runAgent(main);

// Export for testing
export { getAppNameLocalization };
