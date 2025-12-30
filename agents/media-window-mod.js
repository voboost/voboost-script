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

let ContextUtils = null;
let ContextClass = null;
let MediaEnum = null;

let mediaServices = null;

let iconDrawables = null;

let config = null;
let languageConfig = null;
let mediaEnums = null;

function changeMediaEnum() {
    try {
        for (let serviceName of mediaServices) {
            if (!Object.prototype.hasOwnProperty.call(config.media, serviceName)) continue;

            const media = config.media[serviceName];

            if (media.pageName === undefined || media.pageName === '') continue;

            const mediaEnum = mediaEnums[serviceName];

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
        }
    } catch (e) {
        logger.error(`${ERROR.CHANGE_ENUM_ERROR} ${e.message}`);
        logger.error(e.stack);
    }
}

function createIconDrawable() {
    const Base64 = Java.use('android.util.Base64');
    const BitmapFactory = Java.use('android.graphics.BitmapFactory');
    const BitmapDrawable = Java.use('android.graphics.drawable.BitmapDrawable');

    const drawable = {};

    try {
        const context = Java.cast(getFieldValue(ContextUtils, 'context'), ContextClass);

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

            const context = Java.cast(getFieldValue(ContextUtils, 'context'), ContextClass);
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

function init() {
    MediaEnum = Java.use('com.qinggan.media.helper.MediaEnum');
    ContextUtils = Java.use('com.qinggan.app.service.utils.ContextUtils');
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

function main() {
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
