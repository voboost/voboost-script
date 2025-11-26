import {
    LANGUAGE_CONFIG_PATH,
    WEATHER_CONFIG_PATH,
    LoadTextFile,
    parseConfig,
} from "./utils.js";

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

const windDirections = [
    { cn: "北风", en: "N", ru: "С", dir: "8" },
    { cn: "东北风", en: "NE", ru: "СВ", dir: "1" },
    { cn: "东风", en: "E", ru: "В", dir: "2" },
    { cn: "东南风", en: "SE", ru: "ЮВ", dir: "3" },
    { cn: "南风", en: "S", ru: "Ю", di: "4" },
    { cn: "西南风", en: "SW", ru: "ЮЗ", dir: "5" },
    { cn: "西风", en: "W", ru: "З", dir: "6" },
    { cn: "西北风", en: "NW", ru: "СЗ", dir: "7" },
];

const TEXTS_EN = {
    // Восход/закат
    sunrise: { en: "Sunrise", ru: "Восход", cn: "日出" },
    sunset: { en: "Sunset", ru: "Закат", cn: "日落" },

    // Уровни ветра (только текст для _en)
    wind0: { en: "Level 0", ru: "Уровень 0", cn: "软风" },
    wind1: { en: "Level 1", ru: "Уровень 1", cn: "轻风" },
    wind2: { en: "Level 2", ru: "Уровень 2", cn: "和缓" },
    wind3: { en: "Level 3", ru: "Уровень 3", cn: "清风" },
    wind4: { en: "Level 4", ru: "Уровень 4", cn: "强风" },
    wind5: { en: "Level 5", ru: "Уровень 5", cn: "劲风" },
    wind6: { en: "Level 6", ru: "Уровень 6", cn: "大风" },
    wind7: { en: "Level 7", ru: "Уровень 7", cn: "烈风" },
    wind8: { en: "Level 8", ru: "Уровень 8", cn: "狂风" },
    wind9: { en: "Level 9", ru: "Уровень 9", cn: "暴风" },

    // Предупреждения (alarm_content и т.п.)
    strongWind: { en: "Strong wind warning", ru: "Предупреждение о сильном ветре", cn: "强风警告" },
    highTemp: { en: "High temperature warning", ru: "Предупреждение о высокой температуре", cn: "高温警告" },
    lowTemp: { en: "Low temperature warning", ru: "Предупреждение о низкой температуре", cn: "低温警告" },
    thunder: { en: "Thunderstorm warning", ru: "Предупреждение о грозе", cn: "雷暴警告" },
    heavyRain: { en: "Heavy rain warning", ru: "Предупреждение о сильном дожде", cn: "暴雨警告" },

    // AQI уровни
    aqiGood: { en: "Good", ru: "Хорошо", cn: "优" },
    aqiModerate: { en: "Moderate", ru: "Умеренно", cn: "良" },
    aqiLightPollution: { en: "Light pollution", ru: "Лёгкое загрязнение", cn: "轻度污染" },
    aqiModeratePollution: { en: "Moderate pollution", ru: "Умеренное загрязнение", cn: "中度污染" },
    aqiHeavyPollution: { en: "Heavy pollution", ru: "Сильное загрязнение", cn: "重度污染" },

    // Статус
    statusSuccess: { en: "Success.", ru: "Успешно.", cn: "请求成功." },
};

const windDirectionsDefault = { cn: "北风", en: "N", ru: "С", dir: "0" };

const weatherMainToChinese = {
    "Clear": "晴", "Clouds": "多云", "Rain": "雨", "Drizzle": "毛毛雨",
    "Thunderstorm": "雷暴", "Snow": "雪", "Mist": "薄雾", "Fog": "雾",
};

function getUserLanguage() {
    if (!languageConfig || !languageConfig.language) return "en";
    const lc = languageConfig.language.toLowerCase();
    return lc === "ru" || lc === "en" || lc === "cn" ? lc : "en";
}

function getEnText(key) {
    const lang = getUserLanguage();
    return TEXTS_EN[key]?.[lang] || TEXTS_EN[key]?.en || key;
}

function getWindLocalizeName(windDirection) {
    var lan = getUserLanguage();
    return {
        cn: windDirection.cn,
        dir: windDirection.dir,
        en: lan === "ru" ? windDirection.ru : windDirection.en,
    };
}

function getWindDirectionName(deg) {
    if (deg === undefined || deg === null) deg = 0;
    if (deg === 0) return getWindLocalizeName(windDirectionsDefault);

    const index = Math.round(deg / 45) % 8;
    return getWindLocalizeName(windDirections[index]);
}

function getWindPowerLevel(speed) {
    let level = "0";
    if (speed < 1.6) level = "0";
    else if (speed < 3.4) level = "1";
    else if (speed < 5.5) level = "2";
    else if (speed < 8.0) level = "3";
    else if (speed < 10.8) level = "4";
    else if (speed < 13.9) level = "5";
    else if (speed < 17.2) level = "6";
    else if (speed < 20.8) level = "7";
    else if (speed < 24.5) level = "8";
    else level = "9";

    return {
        num: level,
        cn: (() => {
            // Оставляем КИТАЙСКИЙ как в оригинале
            const map = {
                "0": "软风", "1": "轻风", "2": "和缓", "3": "清风", "4": "强风",
                "5": "劲风", "6": "大风", "7": "烈风", "8": "狂风", "9": "暴风",
            };
            return map[level] || "软风";
        })(),
        en: getEnText(`wind${level}`), // ← только _en меняется
    };
}

function formatDateISO(date) {
    return date.toISOString().replace("T", " ").substring(0, 19);
}

function getSunTime(date, isSunrise) {
    const baseHour = isSunrise ? 6 : 16;
    const min = Math.floor(Math.random() * 60);
    const sec = Math.floor(Math.random() * 60);
    const d = new Date(date);
    d.setHours(baseHour, min, sec, 0);
    return formatDateISO(d);
}

function clone(obj) {
    return JSON.parse(JSON.stringify(obj));
}

function parseUrlParams(urlStr) {
    const params = {};
    if (!urlStr.includes("?")) return params;
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
    let lang = "en";
    const userLang = getUserLanguage();
    if (userLang === "ru") lang = "ru";
    else if (userLang === "cn") lang = "zh_cn";

    const url = `https://api.openweathermap.org/data/2.5/forecast?lat=${lat}&lon=${lon}&appid=${config.api_key}&units=metric&lang=${lang}`;
    const client = OkHttpClient.$new();
    const request = RequestBuilder.$new().url(url).build();
    const response = client.newCall(request).execute();
    if (!response.isSuccessful()) throw new Error("Forecast HTTP " + response.code());
    return response.body().string();
}

function fetchGeocodeFromNominatim(lat, lon) {
    // Определяем Accept-Language для Nominatim
    let acceptLang = "en-US"; // default
    const userLang = getUserLanguage(); // та же функция, что и выше
    if (userLang === "ru") {
        acceptLang = "ru-RU";
    } else if (userLang === "cn") {
        acceptLang = "zh-CN";
    }

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
    if (!response.isSuccessful()) throw new Error("AQI HTTP " + response.code());
    return response.body().string();
}

function mapOpenWeatherIdToLauncherCode(owId) {
    const id = parseInt(owId, 10);
    if (id >= 200 && id <= 232) return id === 200 || id === 210 || id === 230 ? "04" : "05";
    if (id >= 300 && id <= 321) return "07";
    if (id >= 500 && id <= 504) return id === 500 ? "08" : "09";
    if (id === 511) return "19";
    if (id >= 520 && id <= 531) return "03";
    if (id >= 600 && id <= 602) {
        if (id === 600) return "14";
        if (id === 601) return "15";
        return "16";
    }
    if (id >= 611 && id <= 613) return "06";
    if (id >= 620 && id <= 622) return "13";
    if (id === 701) return "35";
    if (id === 711 || id === 721) return "53";
    if (id === 731 || id === 761) return "29";
    if (id === 741) return "18";
    if (id === 751) return "30";
    if (id === 771) return "32";
    if (id === 781) return "33";
    if (id === 800) return "01";
    if (id === 801 || id === 802) return "01";
    if (id >= 803 && id <= 804) return "02";
    console.log("[-] номер погоды не определен:" + owId);
    return "00";
}

function mapWeatherToChinese(main) {
    return weatherMainToChinese[main] || main;
}

function calculateMoonPhase(date) {
    const start = new Date(date.getFullYear(), 0, 1);
    const diff = date - start;
    const dayOfYear = Math.floor(diff / (1000 * 60 * 60 * 24));
    const phase = (dayOfYear % 29.53) / 29.53;

    if (phase < 0.03) return "新月";
    if (phase < 0.22) return "растущая луна";
    if (phase < 0.28) return "первая четверть";
    if (phase < 0.47) return "прибывающая луна";
    if (phase < 0.53) return "полнолуние";
    if (phase < 0.72) return "убывающая луна";
    if (phase < 0.78) return "последняя четверть";
    return "старая луна";
}

function getMoonTime(date, isRise) {
    const hour = isRise ? 18 : 6;
    return date.toISOString().substring(0, 10) + " " +
        hour.toString().padStart(2, "0") + ":00:00";
}

function calculateAQIFromHumidity(humidity) {
    if (humidity < 30) return "50";
    if (humidity < 50) return "75";
    if (humidity < 70) return "100";
    if (humidity < 85) return "125";
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

function getAQILevel(aqi) {
    const aqiNum = parseInt(aqi);
    if (aqiNum <= 50) return getEnText("aqiGood");
    if (aqiNum <= 100) return getEnText("aqiModerate");
    if (aqiNum <= 150) return getEnText("aqiLightPollution");
    if (aqiNum <= 200) return getEnText("aqiModeratePollution");
    return getEnText("aqiHeavyPollution");
}

function calculatePM25FromData(main) {
    const humidity = main.humidity || 0;
    const pressure = main.pressure || 1013;
    const basePM25 = 20 + (humidity / 10) + ((1013 - pressure) / 10);
    return Math.max(5, Math.min(300, Math.round(basePM25))).toString();
}

function getWeatherAlarm(weatherItem) {
    const main = weatherItem.main || {};
    const weatherArr = weatherItem.weather || [];
    const weather = weatherArr[0] || {};
    const wind = weatherItem.wind || null;

    const currentTemp = main.temp || 0;
    const windSpeed = wind ? (wind.speed || 0) : 0;
    const weatherMain = weather.main || "";

    if (windSpeed > 15) return getEnText("strongWind");
    if (currentTemp > 35) return getEnText("highTemp");
    if (currentTemp < -15) return getEnText("lowTemp");
    if (weatherMain === "Thunderstorm") return getEnText("thunder");
    if (weatherMain === "Rain" && (weather.description || "").includes("Heavy")) return getEnText("heavyRain");
    return "";
}

function getAlarmLevel(weatherData) {
    const alarmContent = getWeatherAlarm(weatherData);
    if (!alarmContent) return "";
    if (alarmContent.includes("强风") || alarmContent.includes("雷暴")) return "黄色";
    if (alarmContent.includes("暴雨") || alarmContent.includes("高温")) return "橙色";
    if (alarmContent.includes("低温")) return "蓝色";
    return "蓝色";
}

function getAlarmLevelCode(weatherData) {
    const level = getAlarmLevel(weatherData);
    switch (level) {
    case "蓝色": return "1";
    case "黄色": return "2";
    case "橙色": return "3";
    case "红色": return "4";
    default: return "";
    }
}

function getAlarmLevelEn(weatherData) {
    const level = getAlarmLevel(weatherData);
    switch (level) {
    case "蓝色": return "Blue";
    case "黄色": return "Yellow";
    case "橙色": return "Orange";
    case "红色": return "Red";
    default: return "";
    }
}

function getAlarmType(weatherData) {
    const alarmContent = getWeatherAlarm(weatherData);
    if (alarmContent.includes("风")) return "大风";
    if (alarmContent.includes("温")) return "温度";
    if (alarmContent.includes("雨")) return "降雨";
    if (alarmContent.includes("雷")) return "雷电";
    return "";
}

function getAlarmTypeEn(weatherData) {
    const type = getAlarmType(weatherData);
    switch (type) {
    case "大风": return "Wind";
    case "温度": return "Temperature";
    case "降雨": return "Rain";
    case "雷电": return "Thunderstorm";
    default: return "";
    }
}

function getAlarmPublishTime() {
    return new Date().toISOString().replace("T", " ").substring(0, 19);
}

function getAdminCodeFromCity(city) {
    const country = city.country || "";
    if (country === "CN") return "100000";
    if (country === "RU") return "200000";
    if (country === "BY") return "300000";
    return "000000";
}

function getAlarmList(weatherData) {
    const alarmContent = getWeatherAlarm(weatherData);
    if (!alarmContent) return [];
    return [{
        alarm_content: alarmContent,
        alarm_level: getAlarmLevel(weatherData),
        alarm_type: getAlarmType(weatherData),
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
            `[+] ${dateStr}: день=${extremes[dateStr].day.time} (${extremes[dateStr].day.temp}°C), ` +
            `ночь=${extremes[dateStr].night.time} (${extremes[dateStr].night.temp}°C)`,
        );
    });
    return extremes;
}

function buildWeatherJson(forecastJsonStr) {
    const forecastJson = JSON.parse(forecastJsonStr); // ← замена JSONObject
    const list = forecastJson.list || [];
    const city = forecastJson.city || {};
    const cityName = city.name || "Unknown";
    const country = city.country || "XX";
    const adname = country + " " + cityName;

    const currentItem = list[0]; // ← замена getJSONObject(0)

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
        const nightTemp = Math.round(extremes.night.temp);

        const dayWind = getWindDirectionName(extremes.day.wind.deg);
        const dayPower = getWindPowerLevel(extremes.day.wind.speed);
        const dayWeather = extremes.day.weather;
        const dayWeatherEN = dayWeather.main || "";

        const nightWind = getWindDirectionName(extremes.night.wind.deg);
        const nightPower = getWindPowerLevel(extremes.night.wind.speed);
        const nightWeather = extremes.night.weather;
        const nightWeatherEN = nightWeather.main || "";

        realDays.push({
            predict_date: dateStr + " 00:00:00",
            day_temp: dayTemp.toString(),
            night_temp: nightTemp.toString(),
            day_weather: mapOpenWeatherIdToLauncherCode(dayWeather.id),
            day_weatherCN: mapWeatherToChinese(dayWeatherEN),
            day_weatherEN: dayWeatherEN,
            night_weather: mapOpenWeatherIdToLauncherCode(nightWeather.id),
            night_weatherCN: mapWeatherToChinese(nightWeatherEN),
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

            sunrise: getSunTime(date, true),
            sunrise_cn: "日出",
            sunrise_en: getEnText("sunrise"),
            sunset: getSunTime(date, false),
            sunset_cn: "日落",
            sunset_en: getEnText("sunset"),

            moonrise: getMoonTime(date, true),
            moonset: getMoonTime(date, false),
            moonphase: calculateMoonPhase(date),

            wind_speed_day: extremes.day.wind.speed.toFixed(1),
            wind_speed_night: extremes.night.wind.speed.toFixed(1),
            description: dayWeather.description || "",
            humidity: extremes.day.main.humidity?.toString() || "0",
            pressure: extremes.day.main.pressure?.toString() || "1013",
        });
    });

    const forecastList = [
        clone(realDays[0]),
        clone(realDays[0]),
        clone(realDays[1]),
        clone(realDays[2]),
        clone(realDays[3]),
        clone(realDays[4]),
        clone(realDays[5]),
    ];

    const lastDay = clone(realDays[5]);
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
        lastDay.sunrise = getSunTime(newDate, true);
        lastDay.sunset = getSunTime(newDate, false);
        lastDay.moonrise = getMoonTime(newDate, true);
        lastDay.moonset = getMoonTime(newDate, false);
        lastDay.moonphase = calculateMoonPhase(newDate);

        forecastList.push(lastDay);
    }

    const liveWether = forecastList[0];
    const aqiValue = calculateAQIFromHumidity(parseInt(liveWether.humidity, 10));

    return JSON.stringify({
        respTime: formatDateISO(new Date()),
        statusCode: "0",
        statusMessage: "请求成功.",
        data: {
            alarm: {
                admin_code: getAdminCodeFromCity(city),
                alarm_content: getWeatherAlarm(currentItem),
                alarm_level: getAlarmLevel(currentItem),
                alarm_level_code: getAlarmLevelCode(currentItem),
                alarm_level_en: getAlarmLevelEn(currentItem),
                alarm_type: getAlarmType(currentItem),
                alarm_type_en: getAlarmTypeEn(currentItem),
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
                level: getAQILevel(aqiValue),
                pm25: calculatePM25FromData(currentItem.main || {}),
                aqi_value: aqiValue,
            },
        },
    });
}

function buildAqiJson(aqiJsonStr, lat, lon) {
    const aqiJson = JSON.parse(aqiJsonStr); // ← замена JSONObject
    const list = aqiJson.list || [];
    if (list.length === 0) throw new Error("No AQI data");
    const item = list[0]; // ← замена getJSONObject(0)
    const main = item.main || {};
    const comp = item.components || {};

    const aqiLevel = main.aqi || 0;
    const respTime = formatDateISO(new Date());
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

function buildGpsInfoJson(nominatimJsonStr, lat, lon) {
    const nominatim = JSON.parse(nominatimJsonStr); // ← замена JSONObject
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
        respTime: formatDateISO(new Date()),
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

function weatherLiveInfo(call, originalRequest, callback) {
    try {
        const url = originalRequest.url().toString();
        const params = parseUrlParams(url);
        const lat = params.latitude;
        const lon = params.longitude;

        if (lat && lon) {
            const fJson = fetchForecast(lat, lon);
            const fakeJson = buildWeatherJson(fJson);

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

function aqiForecastInfo(call, originalRequest, callback) {
    try {
        const url = originalRequest.url().toString();
        const params = parseUrlParams(url);
        const lat = params.latitude;
        const lon = params.longitude;

        if (lat && lon) {
            const aqiJson = fetchAqi(lat, lon);
            const fakeJson = buildAqiJson(aqiJson, lat, lon);

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

function regeocode(call, originalRequest, callback) {
    try {
        const url = originalRequest.url().toString();
        const params = parseUrlParams(url);
        const lat = params.latitude;
        const lon = params.longitude;

        if (lat && lon) {
            const nominatimJson = fetchGeocodeFromNominatim(lat, lon);
            const fakeJson = buildGpsInfoJson(nominatimJson, lat, lon);

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

function enqueueHook() {

    RealCall.enqueue.implementation = function (callback) {
        const originalRequest = this.request();
        const url = originalRequest.url().toString();

        if (url.includes("/cp/weather/weather-live-info")) {
            console.log("[+] Proxying weather (async):", url);
            weatherLiveInfo(this, originalRequest, callback);
        } else if (url.includes("/cp/weather/aqi-forecast-info")) {
            console.log("[+] Proxying AQI request");
            aqiForecastInfo(this, originalRequest, callback);
        } else if (url.includes("/cp/geo/regeocode")) {
            console.log("[+] Proxying reverse geocode request");
            regeocode(this, originalRequest, callback);
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
    // --- Основная логика Frida ---
    init();

    const weatherContent = LoadTextFile(WEATHER_CONFIG_PATH);
    config = parseConfig(weatherContent);

    const languageContent = LoadTextFile(LANGUAGE_CONFIG_PATH);
    languageConfig = parseConfig(languageContent);

    enqueueHook();
    console.log("[*] Weather + Forecast proxy installed (8-day, sync & async)");
}

Java.perform(function () { main(); });
