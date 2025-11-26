/**
 * Removes Chinese country code (+86) prefix from phone numbers.
 *
 * @param {string|number} number - Phone number to process (can be string or number)
 * @returns {string} Phone number without +86 prefix, trimmed of whitespace
 *
 * @example
 * removeChineseCountryCode("+8613812345678")  // Returns: "13812345678"
 * removeChineseCountryCode("13812345678")     // Returns: "13812345678"
 * removeChineseCountryCode(8613812345678)     // Returns: "13812345678"
 */
function removeChineseCountryCode(number) {
    let result = number.toString().trim();

    // Remove +86 prefix if present
    if (result.startsWith("+86")) {
        result = result.substring(3);
        return result;
    }

    return result;
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
        const UtilClass = Java.use("com.qinggan.bluetoothphone.util.Util");

        UtilClass.getAmendNumber.implementation = function (str) {
            return removeChineseCountryCode(str);
        };

        console.log("[*] Successfully hooked and modified getAmendNumber method in bluetoothphone");
    } catch {
        console.log("[!] bluetoothphone.Util class not available in this process");
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
        const PbapProfileManagerClass = Java.use("com.qinggan.bluetoothphone.logic.manager.PbapProfileManager");

        PbapProfileManagerClass.startSync.call(PbapProfileManagerClass);
    } catch (error) {
        console.log("[!] Error processing contact cache:", error.message);
        console.log(error.stack);
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
    console.log("[*] Starting phone number correction hooks");

    hookPhoneNumberFormatter();
    syncContactCache();
}

// Only run in Frida context
if (typeof Java !== "undefined") {
    Java.perform(() => { main(); });
}

// Export for testing
export { removeChineseCountryCode };
