export const ALARM_LEVEL = {
    "蓝色": { code: "1", en: "Blue" },
    "黄色": { code: "2", en: "Yellow" },
    "橙色": { code: "3", en: "Orange" },
    "红色": { code: "4", en: "Red" },
};

export const ALARM_TYPE = {
    "大风": "Wind",
    "温度": "Temperature",
    "降雨": "Rain",
    "雷电": "Thunderstorm",
};

export const CHINESE_WEATHER_TYPE = {
    "Clear": "晴",
    "Clouds": "多云",
    "Rain": "雨",
    "Drizzle": "毛毛雨",
    "Thunderstorm": "雷暴",
    "Snow": "雪",
    "Mist": "薄雾",
    "Fog": "雾",
};

export const WIND_DIRECTIONS = [
    { en: "N", ru: "С", cn: "北风", dir: "8" },
    { en: "NE", ru: "СВ", cn: "东北风", dir: "1" },
    { en: "E", ru: "В", cn: "东风", dir: "2" },
    { en: "SE", ru: "ЮВ", cn: "东南风", dir: "3" },
    { en: "S", ru: "Ю", cn: "南风", dir: "4" },
    { en: "SW", ru: "ЮЗ", cn: "西南风",  dir: "5" },
    { en: "W", ru: "З", cn: "西风", dir: "6" },
    { en: "NW", ru: "СЗ", cn: "西北风", dir: "7" },
];

export const WIND_DIRECTIONS_DEFAULT = { cn: "北风", en: "N", ru: "С", dir: "0" };
