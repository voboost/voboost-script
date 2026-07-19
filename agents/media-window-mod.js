/**
 * Media Window Modification Agent
 *
 * This Frida agent hooks into the media window system to customize media service
 * configurations, icons, and behavior. It allows modification of media enum properties,
 * custom icon drawables, and control over media focus and page opening.
 *
 * @module media-window-mod
 */

import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './media-window-log.js';

import {
    LANGUAGE_CONFIG_PATH,
    MEDIA_SOURCE_CONFIG_PATH,
    loadConfig,
    runAgent,
    setFieldValue,
    getFieldValue,
} from '../lib/utils.js';

const logger = new Logger('media-window-mod');

// Manifest metadata consumed by the manifest generator. `process` is the
// Android process the daemon injects this agent into (hooks
// `com.qingang.asgard.media.general.src.SrcMediaActivity`, which lives in
// the qgmedia app `com.qinggan.media`); `boot:false` = inject as soon as the
// target is reachable.
export const AGENT_META = {
    id: 'media-window',
    process: 'com.qinggan.media',
    boot: false,
};

let ActivityThread = null;
let ContextClass = null;
let MediaEnum = null;

let mediaServices = null;

let iconDrawables = null;

let config = null;
let languageConfig = null;
let mediaEnums = null;

/**
 * Builds media enum configuration from the provided config object and applies it to
 * the provided MediaEnum objects. This is the single implementation shared by
 * `changeMediaEnum()` and is written as a pure-ish function (its only side effects are
 * mutating the passed-in `enums` entries) so it can be tested independently.
 *
 * For each requested service that has a non-empty `pageName` in `configData.media`,
 * this sets `pageName` on the matching `enums[serviceName].service` object, sets the
 * optional `servicePageName`/`serviceName`/`clientId` fields only when they are present
 * and non-empty, and always marks the service as `enable = true`.
 *
 * @param {Object} configData - Configuration object containing media service settings
 * @param {Object} configData.media - Media services configuration
 * @param {Array<string>} services - Array of service names to configure
 * @param {Object} enums - Media enum objects to configure. Each entry is expected to be
 *   `{ service: Object, enable: boolean }`; `service` is mutated via `setFieldValue()`
 *   and `enable` is set to `true` for every configured service.
 * @returns {Object} Configuration result with success status and configured services
 *
 * @example
 * const config = {
 *   media: {
 *     WECAR_FLOW: { pageName: 'com.example.app', serviceName: 'WeCarFlow' }
 *   }
 * };
 * const services = ['WECAR_FLOW'];
 * const enums = { WECAR_FLOW: { service: {}, enable: false } };
 * buildMediaEnumConfig(config, services, enums);
 */
function buildMediaEnumConfig(configData, services, enums) {
    if (!configData || typeof configData !== 'object') {
        return { success: false, configured: [] };
    }

    if (!configData.media || typeof configData.media !== 'object') {
        return { success: false, configured: [] };
    }

    if (!Array.isArray(services) || services.length === 0) {
        return { success: false, configured: [] };
    }

    if (!enums || typeof enums !== 'object') {
        return { success: false, configured: [] };
    }

    const configured = [];

    for (let serviceName of services) {
        if (!Object.prototype.hasOwnProperty.call(configData.media, serviceName)) {
            continue;
        }

        const media = configData.media[serviceName];

        if (!media || typeof media !== 'object') {
            continue;
        }

        if (media.pageName === undefined || media.pageName === '') {
            continue;
        }

        const mediaEnum = enums[serviceName];

        if (!mediaEnum || !mediaEnum.service || typeof mediaEnum.service !== 'object') {
            continue;
        }

        setFieldValue(mediaEnum.service, 'pageName', media.pageName);

        if (media.servicePageName !== undefined && media.servicePageName !== '') {
            setFieldValue(mediaEnum.service, 'servicePageName', media.servicePageName);
        }

        if (media.serviceName !== undefined && media.serviceName !== '') {
            setFieldValue(mediaEnum.service, 'serviceName', media.serviceName);
        }

        if (media.clientId !== undefined && media.clientId !== '') {
            setFieldValue(mediaEnum.service, 'clientId', media.clientId);
        }

        mediaEnum.enable = true;

        configured.push({
            serviceName,
            pageName: media.pageName,
            servicePageName: media.servicePageName,
            serviceName_: media.serviceName,
            clientId: media.clientId,
        });
    }

    return { success: true, configured };
}

/**
 * Applies media enum configuration changes to the actual MediaEnum objects.
 * This function modifies the Java objects using the Frida API via `buildMediaEnumConfig()`.
 */
function changeMediaEnum() {
    try {
        buildMediaEnumConfig(config, mediaServices, mediaEnums);
    } catch (e) {
        logger.error(`${ERROR.CHANGE_ENUM_ERROR} ${e.message}`);
        logger.error(e.stack);
    }
}

/**
 * Creates icon drawables from base64-encoded images in the configuration.
 * Converts base64 strings to Android Bitmap and BitmapDrawable objects.
 *
 * @returns {Object} Map of service names to drawable objects with icon and name
 */
function createIconDrawable() {
    const Base64 = Java.use('android.util.Base64');
    const BitmapFactory = Java.use('android.graphics.BitmapFactory');
    const BitmapDrawable = Java.use('android.graphics.drawable.BitmapDrawable');

    const drawable = {};

    try {
        const application = ActivityThread.currentApplication();
        if (!application) {
            logger.error(ERROR.APPLICATION_NULL);
            return drawable;
        }

        const context = application.getApplicationContext();

        for (let serviceName of mediaServices) {
            if (!Object.prototype.hasOwnProperty.call(config.media, serviceName)) continue;

            const media = config.media[serviceName];

            if (media.pageName === undefined || media.pageName === '') continue;
            if (media.iconLarge === undefined || media.iconLarge === '') continue;

            const bytes = Base64.decode(media.iconLarge, getFieldValue(Base64, 'DEFAULT'));
            const iconBitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
            const iconDrawable = BitmapDrawable.$new(context.getResources(), iconBitmap);

            let nameText = '';
            if (media.name !== undefined && media.name !== '') {
                if (Object.prototype.hasOwnProperty.call(media.name, languageConfig.language)) {
                    nameText = media.name[languageConfig.language];
                }
            }

            drawable[serviceName] = { icon: iconDrawable, name: nameText };
        }
    } catch (e) {
        logger.error(`${ERROR.CREATE_ICON_ERROR} ${e.message}`);
        logger.error(e.stack);
    }

    return drawable;
}

/**
 * Hooks into MediaSrcAdapter$MediaSrcHolder.bindView to customize media source icons and names.
 * Replaces the default icon and name with custom values from configuration.
 */
function bindViewHook() {
    const MediaSrcHolder = Java.use(
        'com.qingang.asgard.media.general.src.MediaSrcAdapter$MediaSrcHolder'
    );

    MediaSrcHolder.bindView.implementation = function (i) {
        this.bindView.call(this, i);

        try {
            const mediaEnum = Java.cast(
                getFieldValue(this, 'srcMediaBean').getMediaEnum(),
                MediaEnum
            );
            const mediaEnumName = mediaEnum.toString();

            if (!Object.prototype.hasOwnProperty.call(iconDrawables, mediaEnumName)) {
                return;
            }

            const drawable = iconDrawables[mediaEnumName];
            const binding = getFieldValue(this, 'binding');
            const textView = getFieldValue(binding, 'tvName');
            const imageView = getFieldValue(binding, 'ivMain');

            textView.setText.overload('java.lang.CharSequence').call(textView, drawable.name);
            imageView.setImageDrawable
                .overload('android.graphics.drawable.Drawable')
                .call(imageView, drawable.icon);
        } catch (e) {
            logger.error(`${ERROR.BIND_VIEW_ERROR}: ${e.message}`);
            logger.error(e.stack);
        }
    };
}

/**
 * Hooks into AudioPolicyHelper.isMediaFocus to control media focus behavior.
 * Determines if a media service should have audio focus based on the current package.
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

            if (!Object.prototype.hasOwnProperty.call(mediaEnums, mediaName)) {
                return this.isMediaFocus
                    .overload(MediaEnum.$className, 'com.qinggan.audiopolicy.AudioPolicyInfo')
                    .call(this, mediaEnum, audioPolicyInfo);
            }

            const mediaService = mediaEnums[mediaName];

            if (!mediaService.enable) {
                return this.isMediaFocus
                    .overload(MediaEnum.$className, 'com.qinggan.audiopolicy.AudioPolicyInfo')
                    .call(this, mediaEnum, audioPolicyInfo);
            }

            const currentPackage = audioPolicyInfo.getPackageName();
            const mediaPackage = getFieldValue(mediaService.service, 'pageName');
            return currentPackage === mediaPackage;
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
 * Hooks into SrcMediaActivity.openPage to customize how media applications are launched.
 * Intercepts the default page opening behavior and launches configured packages instead.
 */
function openPageHook() {
    const SrcMediaActivity = Java.use('com.qingang.asgard.media.general.src.SrcMediaActivity');
    const MediaJumpUtils = Java.use('com.qinggan.media.helper.app.MediaJumpUtils');
    const Intent = Java.use('android.content.Intent');
    const Integer = Java.use('java.lang.Integer');

    SrcMediaActivity.openPage.overload(
        'com.qingang.asgard.media.general.src.MediaResEnum'
    ).implementation = function (mediaResEnum) {
        try {
            const mediaEnum = Java.cast(getFieldValue(mediaResEnum, 'mediaEnum'), MediaEnum);
            const mediaEnumName = mediaEnum.toString();

            if (!Object.prototype.hasOwnProperty.call(mediaEnums, mediaEnumName)) {
                this.openPage
                    .overload('com.qingang.asgard.media.general.src.MediaResEnum')
                    .call(this, mediaResEnum);
                return;
            }

            const mediaService = mediaEnums[mediaEnumName];
            if (!mediaService) {
                this.openPage
                    .overload('com.qingang.asgard.media.general.src.MediaResEnum')
                    .call(this, mediaResEnum);
                return;
            }

            const packageName = getFieldValue(mediaService.service, 'pageName');
            const handler = getFieldValue(this, 'handler');
            handler.removeMessages.overload('int').call(handler, 1);

            const application = ActivityThread.currentApplication();
            if (!application) {
                logger.error(ERROR.APPLICATION_NULL);
                this.openPage
                    .overload('com.qingang.asgard.media.general.src.MediaResEnum')
                    .call(this, mediaResEnum);
                return;
            }

            const context = application.getApplicationContext();
            const intent = context.getPackageManager().getLaunchIntentForPackage(packageName);
            intent.addFlags(0x10000000);

            const starAppNamesParams = Java.array('java.lang.Class', [
                ContextClass.class,
                Intent.class,
                getFieldValue(Integer, 'TYPE'),
            ]);
            const starAppMethod = MediaJumpUtils.class.getDeclaredMethod(
                'starApp',
                starAppNamesParams
            );

            starAppMethod.setAccessible(true);

            const starAppParams = Java.array('java.lang.Object', [
                context,
                intent,
                Integer.valueOf(0),
            ]);
            starAppMethod.invoke(null, starAppParams);
        } catch (e) {
            logger.error(`${ERROR.OPEN_PAGE_ERROR}: ${e.message}`);
            logger.error(e.stack);
        }
    };
}

/**
 * Initializes the agent by loading Java classes, configurations, and setting up
 * the media enum structure.
 */
function init() {
    MediaEnum = Java.use('com.qinggan.media.helper.MediaEnum');
    ActivityThread = Java.use('android.app.ActivityThread');
    ContextClass = Java.use('android.content.Context');

    mediaServices = ['WECAR_FLOW', 'XMLA_MUSIC', 'RADIO_YUNTING'];

    mediaEnums = {
        WECAR_FLOW: { service: getFieldValue(MediaEnum, 'WECAR_FLOW'), active: false },
        XMLA_MUSIC: { service: getFieldValue(MediaEnum, 'XMLA_MUSIC'), active: false },
        RADIO_YUNTING: { service: getFieldValue(MediaEnum, 'RADIO_YUNTING'), active: false },
    };

    // Load language config with full parameter support
    // Priority: 1) params.config, 2) params.configPath, 3) LANGUAGE_CONFIG_PATH
    languageConfig = loadConfig(LANGUAGE_CONFIG_PATH, logger);

    // Load media config with full parameter support
    // Priority: 1) params.config, 2) params.configPath, 3) MEDIA_SOURCE_CONFIG_PATH
    config = loadConfig(MEDIA_SOURCE_CONFIG_PATH, logger);

    // Config is required for this agent
    if (!config) {
        logger.error(ERROR.CONFIG_NOT_AVAILABLE);
        return;
    }

    iconDrawables = createIconDrawable();
}

/**
 * Main entry point for the media window modification agent.
 * Initializes all hooks and applies media enum modifications.
 */
export function main() {
    logger.info(INFO.STARTING);

    init();

    // Config validation already done in init()
    changeMediaEnum();

    config = null;

    bindViewHook();
    openPageHook();
    isMediaFocusHook();

    logger.info(INFO.STARTED);
}

runAgent(main);

// Export for testing
export { buildMediaEnumConfig };
