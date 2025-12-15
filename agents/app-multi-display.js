/**
 * Multi-Display Application Hook Agent
 *
 * This Frida agent hooks into Android's MultiDisplayImpl to control which applications
 * can be transferred between displays.
 *
 * It reads configuration from a JSON file and overrides the system's whitelist check:
 * - Apps with 1 screen in config: locked to a single display
 * - Apps with 2 screens in config: can be transferred between displays
 *
 * @module app-multi-display
 */

import { Logger } from "../lib/logger.js";

import {
    APP_VIEWPORT_CONFIG_PATH,
    LoadTextFile,
    parseConfig,
} from "../lib/utils.js";

const logger = new Logger("app-multi-display");

let config = null;

/**
 * Checks if an application can be transferred between displays.
 *
 * Applications can be configured in two ways:
 * - Single screen (1 screen): App is locked to one specific display
 * - Multi-display (2 screens): App can be transferred between displays
 *
 * @param {string} packageName - The Android package name to check
 * @param {Array<Object>} apps - Array of app configuration objects
 * @param {string} apps[].package - The package name
 * @param {Array<string>} apps[].screen - Array of screen identifiers (1 or 2 screens)
 * @returns {boolean|null} True if app can be transferred between displays (2 screens),
 *                         false if locked to single display (1 screen),
 *                         null if package not found in configuration
 *
 * @example
 * const apps = [
 *   { package: "com.example.transferable", screen: ["main", "third"] },  // Can move between screens
 *   { package: "com.example.locked", screen: ["main"] }                  // Locked to one screen
 * ];
 * isMultiDisplayApp("com.example.transferable", apps); // returns true
 * isMultiDisplayApp("com.example.locked", apps); // returns false
 * isMultiDisplayApp("com.unknown.app", apps); // returns null
 */
function isMultiDisplayApp(packageName, apps) {
    for (let app of apps) {
        if (packageName === app.package) {
            return app.screen.length > 1;
        }
    }

    return null;
}

/**
 * Hooks the MultiDisplayImpl.isWhiteListApp method to override the system's
 * multi-display whitelist with custom configuration.
 *
 * This function intercepts calls to check if an app can be transferred between displays.
 * Returns the configured value if the app is in our config, otherwise falls back
 * to the original implementation.
 *
 * @throws {Error} If the MultiDisplayImpl class cannot be found or hooked
 */
function hookMultiDisplayWhitelist() {
    try {
        var MultiDisplayImpl = Java.use("com.qinggan.systemservice.multidisplay.MultiDisplayImpl");

        MultiDisplayImpl.isWhiteListApp.implementation = function (packageName) {
            logger.debug(`Checking multi-display status for: ${packageName}`);
            const result = isMultiDisplayApp(packageName, config.apps);

            if (result !== null) {
                return result;
            }

            return this.isWhiteListApp.call(MultiDisplayImpl, packageName);
        };
    } catch (e) {
        logger.error(`Error in hook: ${e.message}`);
        logger.error(e.stack);
    }
}

/**
 * Main entry point for the agent.
 * Loads the viewport configuration and initializes the multi-display hook.
 */
function main() {
    const appViewPortContent = LoadTextFile(APP_VIEWPORT_CONFIG_PATH);

    config = parseConfig(appViewPortContent);
    hookMultiDisplayWhitelist();

    logger.info("Multi-display hook installed");
}

// Only run in Frida context
if (typeof Java !== "undefined") {
    Java.perform(function () { main(); });
}

// Export for testing
export { isMultiDisplayApp };
