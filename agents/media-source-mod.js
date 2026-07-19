import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './media-source-log.js';

import {
    LANGUAGE_CONFIG_PATH,
    MEDIA_SOURCE_CONFIG_PATH,
    loadConfig,
    runAgent,
    getFieldValue,
    setFieldValue,
    scheduleOnMainThreadSafe,
    getAndroidContext,
} from '../lib/utils.js';

const logger = new Logger('media-source-mod');

// Manifest metadata consumed by the manifest generator. Targets the media
// card on the launcher's home screen (hooks `com.pateo.voyah.mediaCard.home.*`
// and `com.qinggan.launcher.base.utils.AppLauncher`), so the host process is
// `com.qinggan.app.launcher`. `boot:false` = inject as soon as the target is
// reachable (spawn gating handles earliest reach; no boot gate needed).
export const AGENT_META = {
    id: 'media-source',
    process: 'com.qinggan.app.launcher',
    boot: false,
};

let MediaBeanInter = null;
let MediaTabHolder = null;
let MediaEnum = null;
let BigMediaView97cV2 = null;

let WECAR_FLOW = null;
let XMLA_MUSIC = null;
let RADIO_YUNTING = null;

let mediaServices = null;

let iconDrawables = null;

let config = null;
let languageConfig = null;

/**
 * Builds a service name to page name map from the media configuration.
 * Extracts pageName values from each media service configuration.
 *
 * Note: this is the reverse mapping direction of `media-key-mod.js`'s
 * (unrelated, module-local) `buildPageNameMap`, which maps pageName -> entry.
 * This function is named distinctly to avoid confusion with that one.
 *
 * @param {Object} mediaConfig - The media configuration object
 * @returns {Object} Map of service names to page names
 *
 * @example
 * const config = { media: { WECAR_FLOW: { pageName: 'com.example.app' } } };
 * const map = buildServiceToPageNameMap(config);
 * // Returns: { WECAR_FLOW: 'com.example.app' }
 */
export function buildServiceToPageNameMap(mediaConfig) {
    if (!mediaConfig || typeof mediaConfig !== 'object') {
        return {};
    }

    if (!mediaConfig.media || typeof mediaConfig.media !== 'object') {
        return {};
    }

    const pageNameMap = {};

    for (const [serviceName, serviceData] of Object.entries(mediaConfig.media)) {
        if (serviceData && typeof serviceData === 'object' && serviceData.pageName) {
            pageNameMap[serviceName] = serviceData.pageName;
        }
    }

    return pageNameMap;
}

/**
 * Builds service configuration array from media config.
 * Creates an array of service objects with enable and autoPlay flags.
 *
 * @param {Object} mediaConfig - The media configuration object
 * @param {Array} services - Array of service objects with name and media properties
 * @returns {Array} Array with one entry per input service (same length as
 *  `services`), each with `enable`/`autoPlay` flags set; `enable`/`autoPlay`
 *  are `false` for every entry when `mediaConfig` is missing/invalid. Only
 *  returns an empty array when `services` itself is not a non-empty array.
 *
 * @example
 * const config = { media: { WECAR_FLOW: { pageName: 'com.app', autoPlay: true } } };
 * const services = [{ name: 'WECAR_FLOW', media: mediaEnum }];
 * const result = buildServiceConfig(config, services);
 * // Returns: [{ name: 'WECAR_FLOW', media: mediaEnum, enable: true, autoPlay: true }]
 */
export function buildServiceConfig(mediaConfig, services) {
    if (!Array.isArray(services)) {
        return [];
    }

    if (!mediaConfig || typeof mediaConfig !== 'object') {
        return services.map((service) => ({
            ...service,
            enable: false,
            autoPlay: false,
        }));
    }

    if (!mediaConfig.media || typeof mediaConfig.media !== 'object') {
        return services.map((service) => ({
            ...service,
            enable: false,
            autoPlay: false,
        }));
    }

    return services.map((service) => {
        const serviceData = mediaConfig.media[service.name];
        const hasValidConfig = Boolean(
            serviceData &&
            typeof serviceData === 'object' &&
            serviceData.pageName &&
            serviceData.pageName !== ''
        );

        return {
            ...service,
            enable: hasValidConfig,
            autoPlay: hasValidConfig && serviceData.autoPlay === true,
        };
    });
}

/**
 * Validates the media source configuration object.
 * Checks for required properties and structure.
 *
 * @param {Object} mediaConfig - The configuration object to validate
 * @returns {boolean} True if configuration is valid, false otherwise
 */
function validateConfig(mediaConfig) {
    if (!mediaConfig || typeof mediaConfig !== 'object') {
        logger.error(ERROR.CONFIG_INVALID);
        return false;
    }

    if (!mediaConfig.media || typeof mediaConfig.media !== 'object') {
        logger.error(ERROR.MEDIA_PROPERTY_MISSING);
        return false;
    }

    return true;
}

/**
 * Changes media enum properties based on configuration.
 * Updates pageName, servicePageName, serviceName, and clientId for each configured service.
 */
function changeMediaEnum() {
    const pageNameMap = buildServiceToPageNameMap(config);

    mediaServices = buildServiceConfig(config, mediaServices);

    for (let service of mediaServices) {
        if (!service.enable) continue;

        const media = config.media[service.name];
        const serviceMedia = service.media;

        setFieldValue(serviceMedia, 'pageName', pageNameMap[service.name]);

        if (media.servicePageName !== undefined && media.servicePageName !== '') {
            setFieldValue(serviceMedia, 'servicePageName', media.servicePageName);
        }

        if (media.serviceName !== undefined && media.serviceName !== '') {
            setFieldValue(serviceMedia, 'serviceName', media.serviceName);
        }

        if (media.clientId !== undefined && media.clientId !== '') {
            setFieldValue(serviceMedia, 'clientId', media.clientId);
        }
    }
}

/**
 * Creates icon drawables from base64-encoded images in configuration.
 * Decodes base64 icons and creates Android BitmapDrawable objects.
 *
 * @returns {Object} Map of service names to drawable objects with icon and name
 */
function createIconDrawable() {
    const Base64 = Java.use('android.util.Base64');
    const BitmapFactory = Java.use('android.graphics.BitmapFactory');
    const BitmapDrawable = Java.use('android.graphics.drawable.BitmapDrawable');

    const context = getAndroidContext(logger);
    if (!context) {
        return {};
    }

    const drawable = {};

    for (let service of mediaServices) {
        if (!Object.prototype.hasOwnProperty.call(config.media, service.name)) continue;

        const media = config.media[service.name];

        if (media.pageName === undefined || media.pageName === '') continue;
        if (media.icon === undefined || media.icon === '') continue;

        const bytes = Base64.decode(media.icon, getFieldValue(Base64, 'DEFAULT'));
        const iconBitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
        const iconDrawable = BitmapDrawable.$new(context.getResources(), iconBitmap);

        let nameText = '';
        if (media.name !== undefined && media.name !== '') {
            if (Object.prototype.hasOwnProperty.call(media.name, languageConfig.language)) {
                nameText = media.name[languageConfig.language];
            }
        }

        drawable[service.name] = { icon: iconDrawable, name: nameText };
    }

    return drawable;
}

/**
 * Reconnects media services by updating MediaControlManager instances.
 * Stops current media browser helper, updates configuration, and restarts.
 */
function reconnectMedia() {
    const MediaControlManager = Java.use('com.qinggan.app.mediaCentre.manager.MediaControlManager');
    Java.choose(MediaControlManager.$className, {
        onMatch: function (instance) {
            try {
                const currentMediaType = instance.getMediaType();

                for (let service of mediaServices) {
                    if (!service.enable) continue;
                    if (!currentMediaType.equals(service.media)) continue;

                    const serviceMedia = service.media;
                    const helper = instance.getMediaBrowserHelper();

                    helper.onStop();
                    setFieldValue(helper, 'mMediaType', getFieldValue(serviceMedia, 'mediaId'));
                    setFieldValue(
                        helper,
                        'mMediaServicePackage',
                        getFieldValue(serviceMedia, 'servicePageName')
                    );
                    setFieldValue(
                        helper,
                        'mMediaServiceClass',
                        getFieldValue(serviceMedia, 'serviceName')
                    );
                    helper.onStart();

                    if (service.autoPlay) {
                        waitForConnection(instance);
                    }
                }
            } catch (e) {
                logger.error(`${ERROR.RECONNECT_ERROR} ${e}`);
                logger.error(e.stack);
            }
        },
        onComplete: function () {},
    });
}

/**
 * Waits for media service connection and triggers playback when connected.
 * Polls connection status with exponential backoff up to maxAttempts.
 *
 * @param {Object} instance - MediaControlManager instance to check connection status
 */
function waitForConnection(instance) {
    const delay = 5000;
    const maxAttempts = 5;
    let attempts = 0;

    const checkConnected = () => {
        attempts++;

        if (attempts >= maxAttempts) return;

        if (!instance) return;

        try {
            if (instance.isConnected()) {
                instance.play();
                return;
            }

            // Continue checking
            setTimeout(() => checkConnected(), delay);
        } catch (e) {
            logger.error(`${ERROR.CHECK_CONNECTED_ERROR} ${e}`);
            logger.error(e.stack);
        }
    };

    checkConnected();
}

/**
 * Changes tab icons for media services by finding MediaTabHolder instances.
 * Updates icon and name text for configured media services.
 */
function changeTabIcon() {
    Java.choose(MediaTabHolder.$className, {
        onMatch: function (instance) {
            try {
                const mediaBeanInter = Java.cast(
                    getFieldValue(instance, 'mediaBean'),
                    MediaBeanInter
                );

                const mediaEnum = Java.cast(mediaBeanInter.getMediaEnum(), MediaEnum);
                const mediaEnumName = mediaEnum.toString();

                if (!Object.prototype.hasOwnProperty.call(iconDrawables, mediaEnumName)) return;

                const drawable = iconDrawables[mediaEnumName];
                const textView = getFieldValue(instance, 'tvName');
                const imageView = getFieldValue(instance, 'ivIcon');

                textView.setText.overload('java.lang.CharSequence').call(textView, drawable.name);
                imageView.setImageDrawable
                    .overload('android.graphics.drawable.Drawable')
                    .call(imageView, drawable.icon);
            } catch (e) {
                logger.error(`${ERROR.BIND_VIEW_ERROR} ${e.message}`);
                logger.error(e.stack);
            }
        },
        onComplete: function () {},
    });
}

/**
 * Hooks into MediaTabHolder.bindView to customize media tab appearance.
 * Replaces icon and name for configured media services when tabs are bound.
 */
function bindViewHook() {
    MediaTabHolder.bindView.implementation = function (dataIndex) {
        this.bindView.call(this, dataIndex);
        try {
            const mediaBeanInter = Java.cast(getFieldValue(this, 'mediaBean'), MediaBeanInter);

            const mediaEnum = Java.cast(mediaBeanInter.getMediaEnum(), MediaEnum);
            const mediaEnumName = mediaEnum.toString();

            if (!Object.prototype.hasOwnProperty.call(iconDrawables, mediaEnumName)) return;

            const drawable = iconDrawables[mediaEnumName];

            const textView = getFieldValue(this, 'tvName');
            const imageView = getFieldValue(this, 'ivIcon');

            textView.setText.overload('java.lang.CharSequence').call(textView, drawable.name);
            imageView.setImageDrawable
                .overload('android.graphics.drawable.Drawable')
                .call(imageView, drawable.icon);
        } catch (e) {
            logger.error(`${ERROR.BIND_VIEW_ERROR} ${e.message}`);
            logger.error(e.stack);
        }
    };
}

/**
 * Hooks into BigMediaView97cV2.updateTitleUI to customize media title display.
 * Updates icon and name in the big media view when title UI is refreshed.
 */
function updateTitleUIHook() {
    BigMediaView97cV2.updateTitleUI.implementation = function (mediaBeanInter) {
        try {
            this.updateTitleUI.call(this, mediaBeanInter);

            if (mediaBeanInter === null) return;

            const mediaEnum = Java.cast(mediaBeanInter.getMediaEnum(), MediaEnum);
            const mediaEnumName = mediaEnum.toString();

            if (!Object.prototype.hasOwnProperty.call(iconDrawables, mediaEnumName)) return;

            const drawable = iconDrawables[mediaEnumName];

            const textView = getFieldValue(getFieldValue(this, 'binding'), 'tvMediaName');
            const imageView = getFieldValue(getFieldValue(this, 'binding'), 'mediaIcon');

            textView.setText.overload('java.lang.CharSequence').call(textView, drawable.name);
            imageView.setImageDrawable
                .overload('android.graphics.drawable.Drawable')
                .call(imageView, drawable.icon);
        } catch (e) {
            logger.error(`${ERROR.UPDATE_TITLE_ERROR} ${e.message}`);
            logger.error(e.stack);
        }
    };
}

/**
 * Hooks into BigMediaView97cV2.openMediaPage to customize media page launching.
 * Launches configured package instead of default media page.
 */
function openMediaPageHook() {
    const AppLauncher = Java.use('com.qinggan.launcher.base.utils.AppLauncher');

    BigMediaView97cV2.openMediaPage.implementation = function () {
        const curMediaEnum = getFieldValue(this, 'mediaInfoHelper').getCurMediaEnum();
        const mediaEnumName = curMediaEnum.toString();

        if (!Object.prototype.hasOwnProperty.call(config.media, mediaEnumName)) {
            this.openMediaPage.call(this);
            return;
        }

        const media = config.media[mediaEnumName];
        const packageName = media.pageName;

        if (packageName === undefined || packageName === '') {
            this.openMediaPage.call(this);
            return;
        }

        try {
            const context = getAndroidContext(logger);
            if (!context) {
                return;
            }

            const intent = context.getPackageManager().getLaunchIntentForPackage(packageName);
            intent.addFlags(0x10000000);

            AppLauncher.startApp(context, intent, 0);
        } catch (e) {
            logger.error(`${ERROR.OPEN_PAGE_ERROR} ${e.message}`);
            logger.error(e.stack);
        }
    };
}

/**
 * Hooks into MediaJumpUtils.getStartIntent to provide custom launch intents.
 * Returns launch intent for configured package instead of default.
 *
 * @returns {Object|null} Android Intent object or null
 */
function getStartIntentHook() {
    const MediaJumpUtils = Java.use('com.qinggan.media.helper.app.MediaJumpUtils');

    MediaJumpUtils.getStartIntent.implementation = function (mediaEnum) {
        const mediaEnumName = mediaEnum.toString();

        if (!Object.prototype.hasOwnProperty.call(config.media, mediaEnumName)) {
            return this.getStartIntent.call(this, mediaEnum);
        }

        const media = config.media[mediaEnumName];
        const packageName = media.pageName;

        if (packageName === undefined || packageName === '') {
            return this.getStartIntent.call(this, mediaEnum);
        }

        try {
            const context = getAndroidContext(logger);
            if (!context) {
                return null;
            }

            const intent = context.getPackageManager().getLaunchIntentForPackage(packageName);
            return intent;
        } catch (e) {
            logger.error(`${ERROR.GET_INTENT_ERROR} ${e.message}`);
            logger.error(e.stack);
        }
        return null;
    };
}

/**
 * Hooks into AudioPolicyHelper.isMediaFocus to check media focus correctly.
 * Compares package names for configured media services.
 *
 * @returns {boolean} True if media has focus, false otherwise
 */
function isMediaFocusHook() {
    const AudioPolicyHelper = Java.use('com.qinggan.media.helper.AudioPolicyHelper');

    AudioPolicyHelper.isMediaFocus.overload(
        MediaEnum.$className,
        'com.qinggan.audiopolicy.AudioPolicyInfo'
    ).implementation = function (mediaEnum, audioPolicyInfo) {
        if (mediaEnum === null || audioPolicyInfo === null) {
            return this.isMediaFocus
                .overload(MediaEnum.$className, 'com.qinggan.audiopolicy.AudioPolicyInfo')
                .call(this, mediaEnum, audioPolicyInfo);
        }
        try {
            const mediaName = mediaEnum.toString();

            for (let service of mediaServices) {
                if (!service.enable) continue;
                if (service.name !== mediaName) continue;
                const currentPackage = audioPolicyInfo.getPackageName();
                const mediaPackage = getFieldValue(service.media, 'pageName');
                return currentPackage === mediaPackage;
            }
        } catch (e) {
            logger.error(`${ERROR.MEDIA_FOCUS_ERROR}: ${e.message}`);
            logger.error(e.stack);
        }

        return this.isMediaFocus
            .overload(MediaEnum.$className, 'com.qinggan.audiopolicy.AudioPolicyInfo')
            .call(this, mediaEnum, audioPolicyInfo);
    };
}

/**
 * Initializes Java classes, loads configuration, and prepares media services.
 * Sets up all required Java class references and configuration objects.
 *
 * @returns {boolean} True if initialization succeeded and config is valid, false otherwise
 */
function init() {
    MediaBeanInter = Java.use('com.pateo.voyah.mediaCard.home.inter.MediaBeanInter');
    MediaTabHolder = Java.use(
        'com.pateo.voyah.mediaCard.home.view.mediaTab97c.MediaTabAdapter97c$MediaTabHolder'
    );
    MediaEnum = Java.use('com.qinggan.media.helper.MediaEnum');
    BigMediaView97cV2 = Java.use('com.pateo.voyah.mediaCard.home.h97cV2.BigMediaView97cV2');

    WECAR_FLOW = getFieldValue(MediaEnum, 'WECAR_FLOW');
    XMLA_MUSIC = getFieldValue(MediaEnum, 'XMLA_MUSIC');
    RADIO_YUNTING = getFieldValue(MediaEnum, 'RADIO_YUNTING');

    mediaServices = [
        { name: 'WECAR_FLOW', media: WECAR_FLOW, enable: false, autoPlay: false },
        { name: 'XMLA_MUSIC', media: XMLA_MUSIC, enable: false, autoPlay: false },
        { name: 'RADIO_YUNTING', media: RADIO_YUNTING, enable: false, autoPlay: false },
    ];

    // Load language config with full parameter support
    // Priority: 1) params.config, 2) params.configPath, 3) LANGUAGE_CONFIG_PATH
    languageConfig = loadConfig(LANGUAGE_CONFIG_PATH, logger);

    // Load media config with full parameter support
    // Priority: 1) params.config, 2) params.configPath, 3) MEDIA_SOURCE_CONFIG_PATH
    config = loadConfig(MEDIA_SOURCE_CONFIG_PATH, logger);

    // Config is required for this agent
    if (!config) {
        logger.error(ERROR.CONFIG_NOT_AVAILABLE);
        return false;
    }

    // Validate configuration structure
    if (!validateConfig(config)) {
        return false;
    }

    iconDrawables = createIconDrawable();

    return true;
}

/**
 * Main entry point for the media source modification agent.
 * Initializes all hooks and modifications for media services.
 */
export function main() {
    logger.info(INFO.STARTING);

    // Config validation is done inside init(); no need to validate again here.
    if (!init()) {
        return;
    }

    changeMediaEnum();

    scheduleOnMainThreadSafe(reconnectMedia, logger);
    scheduleOnMainThreadSafe(changeTabIcon, logger);

    bindViewHook();
    updateTitleUIHook();
    openMediaPageHook();
    getStartIntentHook();
    isMediaFocusHook();

    logger.info(INFO.STARTED);
}

runAgent(main);
