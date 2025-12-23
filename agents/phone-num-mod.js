import { Logger } from '../lib/logger.js';
import { LOG } from './phone-num-log.js';
import { runAgent } from '../lib/utils.js';

const logger = new Logger('phone-num-mod');

/**
 * Do nothing with phone number except trimming whitespaces.
 *
 * @param {string|number} number - Phone number to process (can be string or number)
 * @returns {string} Phone number trimmed of whitespace
 */
function getAmendNumber(number) {
    return number.toString().trim();
}

/**
 * Hooks into the Bluetooth phone utility class to intercept and modify
 * phone number formatting. Replaces the getAmendNumber method with our
 * custom implementation that removes Chinese country codes.
 *
 * @throws {Error} If the bluetoothphone.Util class is not available
 *
 * @example
 * hookPhoneNumberFormatter(); // Installs the hook
 */
function hookPhoneNumberFormatter() {
    try {
        const UtilClass = Java.use('com.qinggan.bluetoothphone.util.Util');

        UtilClass.getAmendNumber.implementation = getAmendNumber;

        logger.info(LOG.HOOK_INSTALLED);
    } catch {
        logger.debug(LOG.UTIL_NOT_AVAILABLE);
    }
}

/**
 * Triggers synchronization of the contact cache by calling the PBAP profile
 * manager's startSync method. This ensures contact information is refreshed
 * after phone number formatting changes.
 *
 * @throws {Error} If the PbapProfileManager class is not available or sync fails
 *
 * @example
 * syncContactCache(); // Triggers contact synchronization
 */
function syncContactCache() {
    try {
        const PbapProfileManagerClass = Java.use(
            'com.qinggan.bluetoothphone.logic.manager.PbapProfileManager'
        );

        PbapProfileManagerClass.startSync.call(PbapProfileManagerClass);
    } catch (error) {
        logger.error(`${LOG.ERROR_CONTACT_CACHE} ${error.message}`);
        logger.error(error.stack);
    }
}

/**
 * Main entry point for the phone number modification agent.
 * Initializes all hooks and triggers contact cache synchronization.
 */
function main() {
    logger.info(LOG.STARTING);

    hookPhoneNumberFormatter();
    syncContactCache();
}

runAgent(main);

// Export for testing
export { getAmendNumber };
