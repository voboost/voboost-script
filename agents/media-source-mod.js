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

function changeMediaEnum() {
    for (let service of mediaServices) {
        if (!Object.prototype.hasOwnProperty.call(config.media, service.name)) continue;

        const media = config.media[service.name];

        if (media.pageName === undefined || media.pageName === '') continue;

        const serviceMedia = service.media;

        setFieldValue(serviceMedia, 'pageName', media.pageName);

        if (media.servicePageName !== undefined && media.servicePageName !== '') {
            setFieldValue(serviceMedia, 'servicePageName', media.servicePageName);
        }

        if (media.serviceName !== undefined && media.serviceName !== '') {
            setFieldValue(serviceMedia, 'serviceName', media.serviceName);
        }

        if (media.clientId !== undefined && media.clientId !== '') {
            setFieldValue(serviceMedia, 'clientId', media.clientId);
        }

        service.enable = true;
        service.autoPlay = media.autoPlay;
    }
}

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
                    setFieldValue(
                        helper,
                        'mMediaType',
                        getFieldValue(serviceMedia, 'mediaId')
                    );
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

            // Продолжаем проверку
            setTimeout(() => checkConnected(), delay);
        } catch (e) {
            logger.error(`${ERROR.CHECK_CONNECTED_ERROR} ${e}`);
            logger.error(e.stack);
        }
    };

    checkConnected();
}

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
        return;
    }

    iconDrawables = createIconDrawable();
}

function main() {
    logger.info(INFO.STARTING);

    init();

    // Config validation already done in init()
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
