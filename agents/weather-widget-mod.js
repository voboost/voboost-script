/**
 * Weather Widget Modification Agent
 *
 * This Frida agent intercepts weather API requests and proxies them through
 * OpenWeatherMap API to provide weather data in regions where the original
 * service is unavailable.
 *
 * Features:
 * - Weather forecast (8-day)
 * - Air quality index (AQI)
 * - Reverse geocoding
 * - Multi-language support (en/ru/cn)
 *
 * @module weather-widget-mod
 */

import {
    LANGUAGE_CONFIG_PATH,
    WEATHER_CONFIG_PATH,
    LoadTextFile,
    parseConfig,
} from "./utils.js";

import {
    ALARM_LEVEL,
    ALARM_TYPE,
    CHINESE_WEATHER_TYPE,
    WIND_DIRECTIONS,
    WIND_DIRECTIONS_DEFAULT,
} from "./weather-widget-const.js";

import { I18N } from "./weather-widget-i18n.js";

let RealCall = null;
let OkHttpClient = null;
let RequestBuilder = null;
let MediaType = null;
let ResponseBody = null;
let ResponseBuilder = null;
let ResponseProtocol = null;
let Protocol = null;

let config = null;
let languageConfig = null;

/**
 * Gets the user's preferred language from configuration.
 *
 * @returns {string} Language code: "en", "ru", or "cn" (defaults to "en")
 */
function getUserLanguage() {
    if (!languageConfig || !languageConfig.language) {
        return "en";
    }

    const lc = languageConfig.language.toLowerCase();

    return lc === "ru" || lc === "en" || lc === "cn" ? lc : "en";
}

/**
 * Gets localized text for a given key based on user's language preference.
 *
 * @param {string} key - Text key from I18N object
 * @returns {string} Localized text or key if not found
 */
function getLocalizedText(key) {
    const lang = getUserLanguage();

    return I18N[lang][key] || I18N.en[key] || key;
}

/**
 * Gets localized wind direction object.
 *
 * @param {Object} windDirection - Wind direction object with cn, en, ru, dir properties
 * @returns {Object} Localized wind direction with cn, dir, en properties
 */
function getLocalizedWindDirection(windDirection) {
    return {
        cn: windDirection.cn,
        dir: windDirection.dir,
        en: getUserLanguage() === "ru" ? windDirection.ru : windDirection.en,
    };
}

/**
 * Converts wind degree to localized direction name.
 *
 * @param {number|null|undefined} deg - Wind direction in degrees (0-360)
 * @returns {Object} Wind direction object with cn, dir, en properties
 */
function getWindDirectionName(deg) {
    return deg === undefined || deg === null || deg === 0 ?
        getLocalizedWindDirection(WIND_DIRECTIONS_DEFAULT) :
        getLocalizedWindDirection(WIND_DIRECTIONS[Math.round(deg / 45) % 8]);
}

/**
 * Calculates wind power level based on wind speed using Beaufort scale.
 *
 * @param {number} speed - Wind speed in meters per second
 * @returns {Object} Wind level object with num, cn, en properties
 */
function getWindPowerLevel(speed) {
    let level;

    if (speed < 1.6) {
        level = "0";
    } else if (speed < 3.4) {
        level = "1";
    } else if (speed < 5.5) {
        level = "2";
    } else if (speed < 8.0) {
        level = "3";
    } else if (speed < 10.8) {
        level = "4";
    } else if (speed < 13.9) {
        level = "5";
    } else if (speed < 17.2) {
        level = "6";
    } else if (speed < 20.8) {
        level = "7";
    } else if (speed < 24.5) {
        level = "8";
    } else {
        level = "9";
    }

    return {
        num: level,
        cn: (() => {
            return {
                "0": "软风", "1": "轻风", "2": "和缓", "3": "清风", "4": "强风",
                "5": "劲风", "6": "大风", "7": "烈风", "8": "狂风", "9": "暴风",
            }[level] || "软风";
        })(),
        en: getLocalizedText(`wind${level}`),
    };
}

/**
 * Formats a Date object to ISO 8601 string without timezone.
 *
 * @param {Date} date - Date to format
 * @returns {string} Formatted date string "YYYY-MM-DD HH:mm:ss"
 */
function formatDate(date) {
    return date.toISOString().replace("T", " ").substring(0, 19);
}

/**
 * Generates a random sun time (sunrise or sunset) for a given date.
 *
 * @param {Date} date - Base date
 * @param {boolean} isSunrise - True for sunrise (6:xx), false for sunset (16:xx)
 * @returns {string} Formatted time string "YYYY-MM-DD HH:mm:ss"
 */
function generateSunTime(date, isSunrise) {
    const baseHour = isSunrise ? 6 : 16;
    const min = Math.floor(Math.random() * 60);
    const sec = Math.floor(Math.random() * 60);
    const d = new Date(date);

    d.setHours(baseHour, min, sec, 0);

    return formatDate(d);
}

/**
 * Creates a deep clone of an object using JSON serialization.
 *
 * @param {Object} obj - Object to clone
 * @returns {Object} Deep cloned object
 */
function deepClone(obj) {
    return JSON.parse(JSON.stringify(obj));
}

/**
 * Parses URL query parameters into an object.
 *
 * @param {string} urlStr - URL string with query parameters
 * @returns {Object} Key-value pairs of query parameters
 */
function parseUrlParams(urlStr) {
    const params = {};

    if (!urlStr.includes("?")) {
        return params;
    }

    const query = urlStr.split("?")[1].split("#")[0];
    const pairs = query.split("&");

    for (let i = 0; i < pairs.length; i++) {
        const pair = pairs[i].split("=");

        if (pair.length === 2) {
            const key = decodeURIComponent(pair[0]);
            const val = decodeURIComponent(pair[1].replace(/\+/g, " "));

            params[key] = val;
        }
    }

    return params;
}

function fetchForecast(lat, lon) {
    const lang = {
        ru: "ru",
        cn: "zh_cn",
    }[getUserLanguage()] || "en";

    const url = `https://api.openweathermap.org/data/2.5/forecast?lat=${lat}&lon=${lon}&appid=${config.api_key}&units=metric&lang=${lang}`;
    const client = OkHttpClient.$new();
    const request = RequestBuilder.$new().url(url).build();
    const response = client.newCall(request).execute();

    if (!response.isSuccessful()) {
        throw new Error("Forecast HTTP " + response.code());
    }

    return response.body().string();
}

function fetchGeocodeFromNominatim(lat, lon) {
    const acceptLang = {
        ru: "ru-RU",
        cn: "zh-CN",
    }[getUserLanguage()] || "en-US";

    const url = `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}&accept-language=${acceptLang}&zoom=18`;
    const client = OkHttpClient.$new();
    const request = RequestBuilder.$new()
        .url(url)
        .addHeader("User-Agent", "Frida Weather Hook")
        .build();
    const response = client.newCall(request).execute();

    if (!response.isSuccessful()) {
        throw new Error("Nominatim HTTP " + response.code());
    }

    return response.body().string();
}

function fetchAqi(lat, lon) {
    const url = `https://api.openweathermap.org/data/2.5/air_pollution?lat=${lat}&lon=${lon}&appid=${config.api_key}`;
    const client = OkHttpClient.$new();
    const request = RequestBuilder.$new().url(url).build();
    const response = client.newCall(request).execute();

    if (!response.isSuccessful()) {
        throw new Error("AQI HTTP " + response.code());
    }

    return response.body().string();
}

/**
 * Converts OpenWeatherMap weather ID to launcher weather code.
 *
 * @param {string|number} owId - OpenWeatherMap weather condition ID
 * @returns {string} Two-digit launcher weather code
 */
function convertWeatherIdToLauncherCode(owId) {
    const id = parseInt(owId, 10);

    const result = {
        500: "08",
        501: "09",
        502: "09",
        503: "09",
        504: "09",
        511: "19",
        600: "14",
        601: "15",
        602: "16",
        611: "06",
        612: "06",
        613: "06",
        620: "13",
        621: "13",
        622: "13",
        701: "35",
        711: "53",
        721: "53",
        731: "29",
        741: "18",
        751: "30",
        761: "29",
        771: "32",
        781: "33",
        800: "01",
        801: "01",
        802: "01",
        803: "02",
        804: "02",
    }[id];

    if (result) {
        return result;
    }

    if (id >= 200 && id <= 232) {
        return id === 200 || id === 210 || id === 230 ? "04" : "05";
    }

    if (id >= 300 && id <= 321) {
        return "07";
    }

    if (id >= 520 && id <= 531) {
        return "03";
    }

    console.log("[-] Weather code not defined: " + owId);
    return "00";
}

/**
 * Gets Chinese weather name from English weather main type.
 *
 * @param {string} main - Weather main type (e.g., "Clear", "Clouds")
 * @returns {string} Chinese weather name or original if not found
 */
function getChineseWeatherName(main) {
    return CHINESE_WEATHER_TYPE[main] || main;
}

function getMoonPhaseName(date) {
    const start = new Date(date.getFullYear(), 0, 1);
    const diff = date - start;
    const dayOfYear = Math.floor(diff / (1000 * 60 * 60 * 24));
    const phase = (dayOfYear % 29.53) / 29.53;

    if (phase < 0.03) {
        return "新月";
    } else if (phase < 0.22) {
        return "растущая луна";
    } else if (phase < 0.28) {
        return "первая четверть";
    } else if (phase < 0.47) {
        return "прибывающая луна";
    } else if (phase < 0.53) {
        return "полнолуние";
    } else if (phase < 0.72) {
        return "убывающая луна";
    } else if (phase < 0.78) {
        return "последняя четверть";
    }

    return "старая луна";
}

function generateMoonTime(date, isRise) {
    const hour = isRise ? 18 : 6;

    return date.toISOString()
        .substring(0, 10) +
        " " +
        hour.toString().padStart(2, "0") +
        ":00:00";
}

/**
 * Estimates AQI value from humidity percentage.
 *
 * @param {number} humidity - Humidity percentage (0-100)
 * @returns {string} Estimated AQI value as string
 */
function estimateAqiFromHumidity(humidity) {
    if (humidity < 30) {
        return "50";
    } else if (humidity < 50) {
        return "75";
    } else if (humidity < 70) {
        return "100";
    } if (humidity < 85) {
        return "125";
    }

    return "150";
}

// function getAQILevel(aqi) {
//     const aqiNum = parseInt(aqi);
//     if (aqiNum <= 50) return "优";
//     if (aqiNum <= 100) return "良";
//     if (aqiNum <= 150) return "轻度污染";
//     if (aqiNum <= 200) return "中度污染";
//     return "重度污染";
// }

/**
 * Gets AQI level description based on AQI value.
 *
 * @param {string|number} aqi - AQI value
 * @returns {string} Localized AQI level description
 */
function getAqiLevel(aqi) {
    const aqiNum = parseInt(aqi);

    if (aqiNum <= 50) {
        return getLocalizedText("aqiGood");
    } else  if (aqiNum <= 100) {
        return getLocalizedText("aqiModerate");
    } else if (aqiNum <= 150) {
        return getLocalizedText("aqiLightPollution");
    } else if (aqiNum <= 200) {
        return getLocalizedText("aqiModeratePollution");
    }

    return getLocalizedText("aqiHeavyPollution");
}

/**
 * Estimates PM2.5 value from weather data.
 *
 * @param {Object} main - Weather main data object with humidity and pressure
 * @returns {string} Estimated PM2.5 value as string (5-300)
 */
function estimatePm25FromWeatherData(main) {
    const humidity = main.humidity || 0;
    const pressure = main.pressure || 1013;
    const basePM25 = 20 + (humidity / 10) + ((1013 - pressure) / 10);

    return Math.max(5, Math.min(300, Math.round(basePM25))).toString();
}

/**
 * Gets weather alarm key based on weather conditions.
 *
 * @param {Object} weatherItem - Weather data item from forecast
 * @returns {string|null} Alarm key or null
 */
function getWeatherAlarmKey(weatherItem) {
    const main = weatherItem.main || {};
    const weatherArr = weatherItem.weather || [];
    const weather = weatherArr[0] || {};
    const wind = weatherItem.wind || null;
    const currentTemp = main.temp || 0;
    const windSpeed = wind ? (wind.speed || 0) : 0;
    const weatherMain = weather.main || "";

    if (windSpeed > 15) {
        return "strongWind";
    } else  if (currentTemp > 35) {
        return "highTemp";
    } else if (currentTemp < -15) {
        return "lowTemp";
    } else if (weatherMain === "Thunderstorm") {
        return "thunder";
    } else if (weatherMain === "Rain" && (weather.description || "").includes("Heavy")) {
        return "heavyRain";
    }

    return null;
}

function getWeatherAlarmContent(weatherItem) {
    const key = getWeatherAlarmKey(weatherItem);

    return key ? getLocalizedText(key) : "";
}

/**
 * Gets alarm level (color) based on alarm key.
 *
 * @param {string|null} alarmKey - Alarm key from getWeatherAlarmKey
 * @returns {string} Alarm level in Chinese or empty string
 */
function getAlarmLevel(alarmKey) {
    if (!alarmKey) {
        return "";
    } else  if (alarmKey === "strongWind" || alarmKey === "thunder") {
        return "黄色";
    } else if (alarmKey === "heavyRain" || alarmKey === "highTemp") {
        return "橙色";
    } else if (alarmKey === "lowTemp") {
        return "蓝色";
    }

    return "蓝色";
}

/**
 * Gets alarm level code from Chinese level string.
 *
 * @param {string} level - Alarm level in Chinese
 * @returns {string} Alarm level code (1-4) or empty string
 */
function getAlarmLevelCode(level) {
    return ALARM_LEVEL[level]?.code || "";
}

/**
 * Gets alarm level in English from Chinese level string.
 *
 * @param {string} level - Alarm level in Chinese
 * @returns {string} Alarm level in English or empty string
 */
function getAlarmLevelEn(level) {
    return ALARM_LEVEL[level]?.en || "";
}

/**
 * Gets alarm type based on alarm key.
 *
 * @param {string|null} alarmKey - Alarm key from getWeatherAlarmKey
 * @returns {string} Alarm type in Chinese or empty string
 */
function getAlarmType(alarmKey) {
    if (alarmKey === "strongWind") {
        return "大风";
    } else  if (alarmKey === "highTemp" || alarmKey === "lowTemp") {
        return "温度";
    } else if (alarmKey === "heavyRain") {
        return "降雨";
    } else if (alarmKey === "thunder") {
        return "雷电";
    }

    return "";
}

/**
 * Gets alarm type in English from Chinese type string.
 *
 * @param {string} type - Alarm type in Chinese
 * @returns {string} Alarm type in English or empty string
 */
function getAlarmTypeEn(type) {
    return ALARM_TYPE[type] || "";
}

function getAlarmPublishTime() {
    return new Date().toISOString().replace("T", " ").substring(0, 19);
}

/**
 * Gets admin code based on city country.
 *
 * @param {Object} city - City object with country property
 * @returns {string} Admin code
 */
function getAdminCodeFromCity(city) {
    return {
        CN: "100000",
        RU: "200000",
        BY: "300000",
    }[city.country] || "000000";
}

function getAlarmList(weatherData) {
    const alarmKey = getWeatherAlarmKey(weatherData);

    if (!alarmKey) return [];

    const alarmLevel = getAlarmLevel(alarmKey);

    return [{
        alarm_content: getWeatherAlarmContent(weatherData),
        alarm_level: alarmLevel,
        alarm_type: getAlarmType(alarmKey),
        publish_time: getAlarmPublishTime(),
    }];
}

function getDailyExtremeTimes(dailyMap) {
    const extremes = {};

    Object.keys(dailyMap).forEach(dateStr => {
        const day = dailyMap[dateStr];
        let bestDayIndex = 0;
        let bestNightIndex = 0;
        let minDayDiff = 24;
        let minNightDiff = 24;

        day.times.forEach((timeStr, index) => {
            const hour = parseInt(timeStr.split(":")[0], 10);
            const dayDiff = Math.abs(hour - 12);

            if (dayDiff < minDayDiff) {
                minDayDiff = dayDiff;
                bestDayIndex = index;
            }

            const nightDiff = Math.min(hour, 24 - hour);

            if (nightDiff < minNightDiff) {
                minNightDiff = nightDiff;
                bestNightIndex = index;
            }
        });

        extremes[dateStr] = {
            day: {
                temp: day.temps[bestDayIndex],
                wind: day.winds[bestDayIndex],
                weather: day.weathers[bestDayIndex],
                time: day.times[bestDayIndex],
                main: day.mains[bestDayIndex],
                pop: day.pops[bestDayIndex],
                visibility: day.visibilities[bestDayIndex],
                clouds: day.cloudsAll[bestDayIndex],
            },
            night: {
                temp: day.temps[bestNightIndex],
                wind: day.winds[bestNightIndex],
                weather: day.weathers[bestNightIndex],
                time: day.times[bestNightIndex],
                main: day.mains[bestNightIndex],
                pop: day.pops[bestNightIndex],
                visibility: day.visibilities[bestNightIndex],
                clouds: day.cloudsAll[bestNightIndex],
            },
        };

        console.log(
            `[+] ${dateStr}: day=${extremes[dateStr].day.time} (${extremes[dateStr].day.temp}°C), ` +
            `night=${extremes[dateStr].night.time} (${extremes[dateStr].night.temp}°C)`,
        );
    });

    return extremes;
}

function buildWeatherResponse(forecastJsonStr) {
    const forecastJson = JSON.parse(forecastJsonStr);
    const list = forecastJson.list || [];
    const city = forecastJson.city || {};
    const cityName = city.name || "Unknown";
    const country = city.country || "XX";
    const adname = country + " " + cityName;
    const currentItem = list[0];
    const dailyMap = {};

    for (let i = 0; i < list.length; i++) {
        const item = list[i];
        const dtTxt = item.dt_txt || "";
        const date = dtTxt.substring(0, 10);
        const time = dtTxt.substring(11, 19);

        if (!dailyMap[date]) {
            dailyMap[date] = {
                temps: [],
                weathers: [],
                winds: [],
                times: [],
                mains: [],
                pops: [],
                visibilities: [],
                cloudsAll: [],
            };
        }

        const m = item.main || {};
        const wArr = item.weather || [];
        const w = wArr[0] || {};
        const wd = item.wind || null;

        dailyMap[date].temps.push(m.temp || 0);
        dailyMap[date].weathers.push(w);
        dailyMap[date].times.push(time);
        dailyMap[date].mains.push(m);
        dailyMap[date].pops.push(item.pop || 0);
        dailyMap[date].visibilities.push(item.visibility || 10000);
        dailyMap[date].cloudsAll.push((item.clouds && item.clouds.all) || 0);

        if (wd) {
            dailyMap[date].winds.push({
                deg: wd.deg || 0,
                speed: wd.speed || 0,
                gust: wd.gust || 0,
            });
        }
    }

    const realDays = [];
    const dates = Object.keys(dailyMap).slice(0, 6);
    const dailyExtremes = getDailyExtremeTimes(dailyMap);

    dates.forEach((dateStr) => {
        const date = new Date(dateStr);
        const extremes = dailyExtremes[dateStr];
        const dayTemp = Math.round(extremes.day.temp);
        const dayWind = getWindDirectionName(extremes.day.wind.deg);
        const dayPower = getWindPowerLevel(extremes.day.wind.speed);
        const dayWeather = extremes.day.weather;
        const dayWeatherEN = dayWeather.main || "";
        const nightTemp = Math.round(extremes.night.temp);
        const nightWind = getWindDirectionName(extremes.night.wind.deg);
        const nightPower = getWindPowerLevel(extremes.night.wind.speed);
        const nightWeather = extremes.night.weather;
        const nightWeatherEN = nightWeather.main || "";

        realDays.push({
            predict_date: dateStr + " 00:00:00",
            day_temp: dayTemp.toString(),
            night_temp: nightTemp.toString(),
            day_weather: convertWeatherIdToLauncherCode(dayWeather.id),
            day_weatherCN: getChineseWeatherName(dayWeatherEN),
            day_weatherEN: dayWeatherEN,
            night_weather: convertWeatherIdToLauncherCode(nightWeather.id),
            night_weatherCN: getChineseWeatherName(nightWeatherEN),
            night_weatherEN: nightWeatherEN,

            day_wind_direct: dayWind.dir,
            day_wind_direct_cn: dayWind.cn,
            day_wind_direct_en: dayWind.en,
            day_wind_power: dayPower.num,
            day_wind_power_cn: dayPower.cn,
            day_wind_power_en: dayPower.en,

            night_wind_direct: nightWind.dir,
            night_wind_direct_cn: nightWind.cn,
            night_wind_direct_en: nightWind.en,
            night_wind_power: nightPower.num,
            night_wind_power_cn: nightPower.cn,
            night_wind_power_en: nightPower.en,

            sunrise: generateSunTime(date, true),
            sunrise_cn: "日出",
            sunrise_en: getLocalizedText("sunrise"),
            sunset: generateSunTime(date, false),
            sunset_cn: "日落",
            sunset_en: getLocalizedText("sunset"),

            moonrise: generateMoonTime(date, true),
            moonset: generateMoonTime(date, false),
            moonphase: getMoonPhaseName(date),

            wind_speed_day: extremes.day.wind.speed.toFixed(1),
            wind_speed_night: extremes.night.wind.speed.toFixed(1),
            description: dayWeather.description || "",
            humidity: extremes.day.main.humidity?.toString() || "0",
            pressure: extremes.day.main.pressure?.toString() || "1013",
        });
    });

    const forecastList = [
        deepClone(realDays[0]),
        deepClone(realDays[0]),
        deepClone(realDays[1]),
        deepClone(realDays[2]),
        deepClone(realDays[3]),
        deepClone(realDays[4]),
        deepClone(realDays[5]),
    ];

    const lastDay = deepClone(realDays[5]);

    if (lastDay) {
        const [datePart] = lastDay.predict_date.split(" ");
        const [y, m, d] = datePart.split("-").map(Number);
        const newDate = new Date(y, m - 1, d);

        newDate.setDate(newDate.getDate() + 1);

        const nextY = newDate.getFullYear();
        const nextM = String(newDate.getMonth() + 1).padStart(2, "0");
        const nextD = String(newDate.getDate()).padStart(2, "0");
        const nextDateStr = `${nextY}-${nextM}-${nextD} 00:00:00`;

        lastDay.predict_date = nextDateStr;
        lastDay.sunrise = generateSunTime(newDate, true);
        lastDay.sunset = generateSunTime(newDate, false);
        lastDay.moonrise = generateMoonTime(newDate, true);
        lastDay.moonset = generateMoonTime(newDate, false);
        lastDay.moonphase = getMoonPhaseName(newDate);

        forecastList.push(lastDay);
    }

    const liveWether = forecastList[0];
    const aqiValue = estimateAqiFromHumidity(parseInt(liveWether.humidity, 10));
    const currentAlarmKey = getWeatherAlarmKey(currentItem);
    const currentAlarmLevel = getAlarmLevel(currentAlarmKey);

    return JSON.stringify({
        respTime: formatDate(new Date()),
        statusCode: "0",
        statusMessage: "请求成功.",
        data: {
            alarm: {
                admin_code: getAdminCodeFromCity(city),
                alarm_content: getWeatherAlarmContent(currentItem),
                alarm_level: currentAlarmLevel,
                alarm_level_code: getAlarmLevelCode(currentAlarmLevel),
                alarm_level_en: getAlarmLevelEn(currentAlarmLevel),
                alarm_type: getAlarmType(currentAlarmKey),
                alarm_type_en: getAlarmTypeEn(getAlarmType(currentAlarmKey)),
                publish_time: getAlarmPublishTime(),
            },
            alarmList: getAlarmList(currentItem),
            live: {
                adname: adname,
                temperature: liveWether.day_temp,
                humidity: liveWether.humidity,
                weather: liveWether.day_weather,
                weather_CN: liveWether.day_weatherCN,
                weather_EN: liveWether.day_weatherEN,
                wind_direction: liveWether.day_wind_direct,
                wind_speed: liveWether.wind_speed_day,
                wind_power: liveWether.day_wind_power,
                pressure: liveWether.pressure,
            },
            forecast: forecastList,
            weatherAirQuality: {
                aqi: aqiValue,
                level: getAqiLevel(aqiValue),
                pm25: estimatePm25FromWeatherData(currentItem.main || {}),
                aqi_value: aqiValue,
            },
        },
    });
}

function buildAqiResponse(aqiJsonStr, lat, lon) {
    const aqiJson = JSON.parse(aqiJsonStr);
    const list = aqiJson.list || [];

    if (list.length === 0) {
        throw new Error("No AQI data");
    }

    const item = list[0];
    const main = item.main || {};
    const comp = item.components || {};
    const aqiLevel = main.aqi || 0;
    const respTime = formatDate(new Date());
    const date = new Date().toISOString().substring(0, 10);

    return JSON.stringify({
        respTime: respTime,
        statusCode: "0",
        statusMessage: "请求成功.",
        data: {
            aqi_point: [
                {
                    point_name: "Station",
                    latitude: lat.toString(),
                    longitude: lon.toString(),
                    value: aqiLevel.toString(),
                    pm25: (comp.pm2_5 || 0).toString(),
                    primary: "PM2.5",
                    pub_time: respTime,
                },
            ],
            aqi_forecast: [
                {
                    date: date,
                    publish_time: respTime,
                    value: aqiLevel.toString(),
                },
            ],
            aqi_history: [],
            aqi_rank: [],
        },
    });
}

function buildGeocodeResponse(nominatimJsonStr, lat, lon) {
    const nominatim = JSON.parse(nominatimJsonStr);
    let province = "北京市", city = "北京市", district = "东城区", country = "中国";
    let adcode = "110000", cityadcode = "110100", districtadcode = "110101";

    if (nominatim.address) {
        const addr = nominatim.address;

        province = addr.state || province;
        city = addr.city || addr.town || city;
        district = addr.suburb || addr.neighbourhood || district;
        country = addr.country || country;
    }

    return JSON.stringify({
        respTime: formatDate(new Date()),
        statusCode: "0",
        statusMessage: "请求成功.",
        data: {
            adcode: adcode,
            city: city,
            cityadcode: cityadcode,
            country: country,
            desc: city,
            district: district,
            districtadcode: districtadcode,
            pos: lat + "," + lon,
            province: province,
            provinceadcode: adcode,
            tel: "",
            crossList: [],
            roadlist: [],
            poilist: [],
        },
    });
}

function handleWeatherLiveRequest(call, originalRequest, callback) {
    try {
        const url = originalRequest.url().toString();
        const params = parseUrlParams(url);
        const lat = params.latitude;
        const lon = params.longitude;

        if (lat && lon) {
            const fJson = fetchForecast(lat, lon);
            const fakeJson = buildWeatherResponse(fJson);
            const mediaType = MediaType.parse("application/json; charset=utf-8");
            const body = ResponseBody.create(mediaType, fakeJson);
            const fakeResponse = ResponseBuilder.$new()
                .protocol(ResponseProtocol)
                .request(originalRequest)
                .code(200)
                .message("OK")
                .body(body)
                .build();

            callback.onResponse(call, fakeResponse);

            return;
        }
    } catch (e) {
        console.error("[-] Async weather proxy error:", e.message);
    }
}

function handleAqiForecastRequest(call, originalRequest, callback) {
    try {
        const url = originalRequest.url().toString();
        const params = parseUrlParams(url);
        const lat = params.latitude;
        const lon = params.longitude;

        if (lat && lon) {
            const aqiJson = fetchAqi(lat, lon);
            const fakeJson = buildAqiResponse(aqiJson, lat, lon);
            const mediaType = MediaType.parse("application/json; charset=utf-8");
            const body = ResponseBody.create(mediaType, fakeJson);
            const fakeResponse = ResponseBuilder.$new()
                .code(200)
                .message("OK")
                .protocol(ResponseProtocol)
                .request(originalRequest)
                .body(body)
                .build();

            callback.onResponse(call, fakeResponse);
        }
    } catch (e) {
        console.error("[-] AQI proxy error:", e.message);
    }
}

function handleGeocodeRequest(call, originalRequest, callback) {
    try {
        const url = originalRequest.url().toString();
        const params = parseUrlParams(url);
        const lat = params.latitude;
        const lon = params.longitude;

        if (lat && lon) {
            const nominatimJson = fetchGeocodeFromNominatim(lat, lon);
            const fakeJson = buildGeocodeResponse(nominatimJson, lat, lon);
            const mediaType = MediaType.parse("application/json; charset=utf-8");
            const body = ResponseBody.create(mediaType, fakeJson);
            const fakeResponse = ResponseBuilder.$new()
                .code(200)
                .message("OK")
                .protocol(ResponseProtocol)
                .request(originalRequest)
                .body(body)
                .build();

            callback.onResponse(call, fakeResponse);
        }
    } catch (e) {
        console.error("[-] Geocode proxy error:", e.message);
    }
}

function installRequestInterceptor() {
    RealCall.enqueue.implementation = function (callback) {
        const originalRequest = this.request();
        const url = originalRequest.url().toString();

        if (url.includes("/cp/weather/weather-live-info")) {
            console.log("[+] Proxying weather (async):", url);

            handleWeatherLiveRequest(this, originalRequest, callback);
        } else if (url.includes("/cp/weather/aqi-forecast-info")) {
            console.log("[+] Proxying AQI request");

            handleAqiForecastRequest(this, originalRequest, callback);
        } else if (url.includes("/cp/geo/regeocode")) {
            console.log("[+] Proxying reverse geocode request");

            handleGeocodeRequest(this, originalRequest, callback);
        }

        return this.enqueue(callback);
    };
}

function init() {
    RealCall = Java.use("okhttp3.RealCall");
    OkHttpClient = Java.use("okhttp3.OkHttpClient");
    RequestBuilder = Java.use("okhttp3.Request$Builder");
    MediaType = Java.use("okhttp3.MediaType");
    ResponseBody = Java.use("okhttp3.ResponseBody");
    ResponseBuilder = Java.use("okhttp3.Response$Builder");

    try {
        Protocol = Java.use("okhttp3.Protocol");
        ResponseProtocol = Protocol.get("http/1.1");
    } catch {
        console.error("[-] Failed to get Protocol");

        return;
    }
}

function main() {
    init();

    config = parseConfig(LoadTextFile(WEATHER_CONFIG_PATH));
    languageConfig = parseConfig(LoadTextFile(LANGUAGE_CONFIG_PATH));
    installRequestInterceptor();

    console.log("[*] Weather + Forecast proxy installed (8-day, sync & async)");
}

// Only run in Frida context
if (typeof Java !== "undefined") {
    Java.perform(() => { main(); });
}

// Export for testing
export {
    getWindPowerLevel,
    getWindDirectionName,
    parseUrlParams,
    formatDate,
    deepClone,
    convertWeatherIdToLauncherCode,
    getChineseWeatherName,
    estimateAqiFromHumidity,
    getAqiLevel,
    estimatePm25FromWeatherData,
    getWeatherAlarmKey,
    getWeatherAlarmContent,
    getAlarmLevel,
    getAlarmLevelCode,
    getAlarmLevelEn,
    getAlarmType,
    getAlarmTypeEn,
    getAdminCodeFromCity,
};
