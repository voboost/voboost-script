import { Logger } from '../lib/logger.js';

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

        logger.info('Phone number hook installed');
    } catch {
        logger.debug('bluetoothphone.Util class not available');
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
        logger.error(`Error processing contact cache: ${error.message}`);
        logger.error(error.stack);
    }
}

/**
 * Main entry point for the phone number modification agent.
 * Initializes all hooks and triggers contact cache synchronization.
 *
 * @example
 * Java.perform(() => { main(); });
 */
function main() {
    logger.info('Starting phone number correction');

    hookPhoneNumberFormatter();
    syncContactCache();
}

// Only run in Frida context
if (typeof Java !== 'undefined') {
    Java.perform(() => {
        main();
    });
}

// Export for testing
export { getAmendNumber };
