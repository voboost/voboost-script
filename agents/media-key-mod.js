/**
 * Media Key Modifier Agent
 *
 * This Frida agent hooks into the EventListenerSink to control media key handling
 * based on configuration. It prevents certain media applications from receiving
 * oriented key events (like volume controls) when they are running or in the foreground.
 *
 * The agent reads a configuration file that specifies which media applications
 * should have their key events blocked based on their page names.
 *
 * @module media-key-mod
 */

import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './media-key-log.js';

import { MEDIA_SOURCE_CONFIG_PATH, loadConfig, runAgent } from '../lib/utils.js';

const logger = new Logger('media-key-mod');

// Initialized to an empty map so handleOrientedKeyHook() stays safe even when
// init() bails out early (e.g. the config fails to load): hasOwnProperty.call()
// on an empty object simply misses, rather than throwing on null.
let mediaPageNames = {};

/**
 * Builds a map of page names from the media configuration.
 *
 * This function extracts page names from the media configuration object
 * and creates a lookup map for quick access. Only entries with valid,
 * non-empty page names are included in the map.
 *
 * @param {Object} config - The configuration object
 * @param {Object} config.media - Object containing media entries
 * @param {Object} config.media[key] - Individual media entry
 * @param {string} config.media[key].pageName - Page name for the media entry
 * @returns {Object} Map of page names to their configuration entries
 *
 * @example
 * const config = {
 *   media: {
 *     spotify: { pageName: "com.spotify.music", enabled: true },
 *     youtube: { pageName: "com.google.youtube", enabled: true }
 *   }
 * };
 * const map = buildPageNameMap(config);
 * // Returns: {
 * //   "com.spotify.music": { pageName: "com.spotify.music", enabled: true },
 * //   "com.google.youtube": { pageName: "com.google.youtube", enabled: true }
 * // }
 */
function buildPageNameMap(config) {
    const pageNameMap = {};

    if (!config || !config.media) {
        return pageNameMap;
    }

    for (const key in config.media) {
        const entry = config.media[key];

        if (entry && typeof entry.pageName === 'string' && entry.pageName.trim() !== '') {
            pageNameMap[entry.pageName] = entry;
        }
    }

    return pageNameMap;
}

/**
 * Hooks the EventListenerSink.handleOrientedKey method to intercept
 * and potentially block oriented key events for configured media applications.
 *
 * The hook checks if the currently running media or top package matches
 * any configured page names. If a match is found, the key event is blocked
 * by returning null instead of processing it.
 *
 * @throws {Error} If the EventListenerSink class cannot be found or hooked
 */
function handleOrientedKeyHook() {
    try {
        const EventListenerSink = Java.use(
            'com.qinggan.keymanager.service.sinks.EventListenerSink'
        );

        EventListenerSink.handleOrientedKey.implementation = function (i, i2) {
            try {
                const mediaRunning = this.mAudioPolicy.value.getRunningMedia();

                if (Object.prototype.hasOwnProperty.call(mediaPageNames, mediaRunning)) {
                    logger.debug(
                        `${DEBUG.CHECKING_MEDIA} ${mediaRunning} ${DEBUG.MEDIA_RUNNING_SUFFIX}`
                    );
                    return null;
                }

                const mediaTop = this.mAudioPolicy.value.getmTopPackageName();

                if (Object.prototype.hasOwnProperty.call(mediaPageNames, mediaTop)) {
                    logger.debug(`${DEBUG.CHECKING_MEDIA} ${mediaTop} ${DEBUG.MEDIA_TOP_SUFFIX}`);
                    return null;
                }
            } catch (e) {
                logger.error(`${ERROR.HANDLE_ORIENTED_KEY} ${e.message}`);
                logger.error(e.stack);
            }

            return this.handleOrientedKey.call(this, i, i2);
        };

        logger.debug(DEBUG.HOOK_INSTALLED);
    } catch (e) {
        logger.error(`${ERROR.HOOK_FAILED} ${e.message}`);
        logger.error(e.stack);
    }
}

/**
 * Initializes the agent by loading the media configuration
 * and building the page name map.
 */
function init() {
    const config = loadConfig(MEDIA_SOURCE_CONFIG_PATH, logger);

    if (!config) {
        logger.error(ERROR.CONFIG_LOAD_FAILED);
        return;
    }

    mediaPageNames = buildPageNameMap(config);
    logger.debug(DEBUG.PAGE_NAME_MAP_BUILT);
    logger.info(INFO.CONFIG_LOADED);
}

/**
 * Main entry point for the media key modifier agent.
 * Initializes configuration and installs the media key hook.
 */
function main() {
    logger.info(INFO.STARTING);

    init();
    handleOrientedKeyHook();

    logger.info(INFO.STARTED);
}

runAgent(main);

// Export for testing
export { buildPageNameMap, init, mediaPageNames };
