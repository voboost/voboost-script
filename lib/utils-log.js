// Log message constants for utils.js

export const ERROR = {
    CONFIG_LOAD_FAILED: 'Config loading failed:',
    FIELD_VALUE_SET: 'Unable to set field value:',
    FIELD_VALUE_GET: 'Unable to get field value:',
    CONTEXT_GET_FAILED: 'Error getting context from ActivityThread:',
    CONTEXT_UNAVAILABLE: 'Unable to get Context',
    REGISTER_CLASS_FAILED: 'Java.registerClass failed, using fallback:',
    REGISTER_CLASS_FALLBACK_FAILED: 'Fallback registerClass also failed:',
};

export const INFO = {
    CONFIG_FROM_PARAM: 'Config loaded from parameter',
    CONFIG_FROM_CUSTOM_PATH: 'Config loading from custom path:',
    CONFIG_FROM_DEFAULT_PATH: 'Config loading from default path:',
    CONFIG_LOADED: 'Config loaded successfully',
};

export const DEBUG = {
    CONFIG_DEFAULT_NOT_AVAILABLE: 'Default config not available:',
    NO_CONFIG_AVAILABLE: 'No config available',
    SCHEDULE_MAIN_THREAD_SKIPPED: 'Skipping Java.scheduleOnMainThread due to:',
    REGISTER_CLASS_FALLBACK_USED: 'Using fallback registerClass for:',
};
