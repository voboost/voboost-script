import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './navbar-launcher-log.js';

import { APP_VIEWPORT_CONFIG_PATH, loadConfig, runAgent, getFieldValue } from '../lib/utils.js';

const logger = new Logger('navbar-launcher-mod');

let config = null;

/**
 * Finds a matching app configuration by package name.
 * @param {string} packageName - The package name to search for
 * @param {Object[]} apps - Array of app configuration objects
 * @returns {Object|null} The matching app configuration or null if not found
 */
export function findMatchingApp(packageName, apps) {
    if (!packageName || !apps || !Array.isArray(apps)) {
        return null;
    }

    for (const app of apps) {
        if (packageName.toString() === app.package) {
            return app;
        }
    }

    return null;
}

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

            const topAppInfo = AppUtils.getTopAppInfo(
                getFieldValue(this, 'mContext'),
                displayId,
                4
            );
            const strArrSplit = topAppInfo.split(getFieldValue(AccountConstantUtil, 'SEPARATOR'));

            const packageName = strArrSplit[0];
            const applicationName = strArrSplit[1];
            // Проверяем, нужно ли принудительно показать панель
            const matchingApp = findMatchingApp(packageName, config.apps);

            if (matchingApp) {
                if (displayId == 0) {
                    this.handleUpdateMainNavigationBar(
                        packageName,
                        applicationName,
                        matchingApp.navigation_bar
                    );
                } else {
                    this.handleUpdateSecondNavigationBar(
                        packageName,
                        applicationName,
                        matchingApp.navigation_bar
                    );
                }
            }
        } catch (e) {
            logger.error(`${ERROR.HOOK} ${e.message}`);
            logger.error(e.stack);
        }
    };
}

function main() {
    logger.info(INFO.STARTING);

    config = loadConfig(APP_VIEWPORT_CONFIG_PATH, logger);

    // Config is required for this agent
    if (!config) {
        logger.error(ERROR.CONFIG_NOT_AVAILABLE);
        return;
    }

    onReceiveHook();
    logger.info(INFO.STARTED);
}

runAgent(main);
