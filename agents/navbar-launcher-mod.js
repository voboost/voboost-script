import { Logger } from '../lib/logger.js';
import { LOG } from './navbar-launcher-log.js';

import { APP_VIEWPORT_CONFIG_PATH, LoadTextFile, parseConfig } from '../lib/utils.js';

const logger = new Logger('navbar-launcher-mod');

let config = null;

function onReceiveHook() {
    const LauncherModel = Java.use('com.qinggan.app.launcher.LauncherModel');
    const AppUtils = Java.use('com.qinggan.launcher.base.utils.AppUtils');
    const AccountConstantUtil = Java.use('com.qinggan.account.AccountConstantUtil');

    // Хук обработки системного события смены активности
    LauncherModel.onReceive.implementation = function (context, intent) {
        // Сначала оригинальная обработка
        this.onReceive.call(this, context, intent);

        try {
            const action = intent.getAction();

            if (action !== 'android.intent.action.TOP_ACTIVITY_CHANGED') return;

            const displayId = intent.getIntExtra('displayId', -1);

            const topAppInfo = AppUtils.getTopAppInfo(this.mContext.value, displayId, 4);
            const strArrSplit = topAppInfo.split(AccountConstantUtil.SEPARATOR.value);

            const packageName = strArrSplit[0];
            const applicationName = strArrSplit[1];
            // Проверяем, нужно ли принудительно показать панель
            for (let app of config.apps) {
                if (packageName.toString() !== app.package) continue;

                if (displayId == 0) {
                    this.handleUpdateMainNavigationBar(
                        packageName,
                        applicationName,
                        app.navigation_bar
                    );
                } else {
                    this.handleUpdateSecondNavigationBar(
                        packageName,
                        applicationName,
                        app.navigation_bar
                    );
                }
                break;
            }
        } catch (e) {
            logger.error(`${LOG.ERROR_HOOK} ${e.message}`);
            logger.error(e.stack);
        }
    };
}

function main() {
    const appViewPortContent = LoadTextFile(APP_VIEWPORT_CONFIG_PATH);
    config = parseConfig(appViewPortContent);

    onReceiveHook();
    logger.info(LOG.HOOK_INSTALLED);
}

Java.perform(function () {
    main();
});
