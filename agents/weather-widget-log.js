export const INFO = {
    STARTING: 'Agent starting',
    STARTED: 'Agent started',
    PROXYING_WEATHER: 'Proxying weather (async):',
    PROXYING_AQI: 'Proxying AQI request',
    PROXYING_GEOCODE: 'Proxying reverse geocode request',
};

export const DEBUG = {
    PROXY_INSTALLED: 'Weather + Forecast proxy installed (8-day, sync & async)',
    WEATHER_CODE_NOT_DEFINED: 'Weather code not defined:',
};

export const ERROR = {
    ASYNC_WEATHER: 'Async weather proxy error:',
    AQI: 'AQI proxy error:',
    GEOCODE: 'Geocode proxy error:',
    PROTOCOL: 'Failed to get Protocol',
    CONFIG_NOT_AVAILABLE: 'Weather config not available or missing api_key',
};
