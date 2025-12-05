import test from 'ava';
import {
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
    getAlarmLevel,
    getAlarmLevelCode,
    getAlarmLevelEn,
    getAlarmType,
    getAlarmTypeEn,
    getAdminCodeFromCity,
} from '../agents/weather-widget-mod.js';

// === Wind Power Level Tests ===
test('getWindPowerLevel returns level 0 for speed < 1.6', (t) => {
    const result = getWindPowerLevel(1.0);
    t.is(result.num, '0');
});

test('getWindPowerLevel returns level 1 for speed 1.6-3.4', (t) => {
    const result = getWindPowerLevel(2.0);
    t.is(result.num, '1');
});

test('getWindPowerLevel returns level 9 for speed >= 24.5', (t) => {
    const result = getWindPowerLevel(30.0);
    t.is(result.num, '9');
});

test('getWindPowerLevel includes cn and en properties', (t) => {
    const result = getWindPowerLevel(5.0);
    t.true(typeof result.cn === 'string');
    t.true(typeof result.en === 'string');
});

// === Wind Direction Tests ===
test('getWindDirectionName returns default for 0 degrees', (t) => {
    const result = getWindDirectionName(0);
    t.is(result.dir, '0');
});

test('getWindDirectionName returns NE for 45 degrees', (t) => {
    const result = getWindDirectionName(45);
    t.is(result.dir, '1');
});

test('getWindDirectionName handles null input', (t) => {
    const result = getWindDirectionName(null);
    t.is(result.dir, '0');
});

test('getWindDirectionName handles undefined input', (t) => {
    const result = getWindDirectionName(undefined);
    t.is(result.dir, '0');
});

// === URL Parsing Tests ===
test('parseUrlParams extracts single parameter', (t) => {
    const result = parseUrlParams('https://api.example.com?lat=55.7');
    t.is(result.lat, '55.7');
});

test('parseUrlParams extracts multiple parameters', (t) => {
    const result = parseUrlParams('https://api.example.com?lat=55.7&lon=37.6');
    t.is(result.lat, '55.7');
    t.is(result.lon, '37.6');
});

test('parseUrlParams returns empty object for URL without query', (t) => {
    const result = parseUrlParams('https://api.example.com');
    t.deepEqual(result, {});
});

test('parseUrlParams handles URL-encoded values', (t) => {
    const result = parseUrlParams('https://api.example.com?name=hello%20world');
    t.is(result.name, 'hello world');
});

// === Date Formatting Tests ===
test('formatDate formats date correctly', (t) => {
    const date = new Date('2024-01-15T10:30:45.000Z');
    const result = formatDate(date);
    t.is(result, '2024-01-15 10:30:45');
});

// === Deep Clone Tests ===
test('deepClone creates independent copy', (t) => {
    const original = { a: 1, b: { c: 2 } };
    const cloned = deepClone(original);
    cloned.b.c = 999;
    t.is(original.b.c, 2);
});

test('deepClone handles arrays', (t) => {
    const original = { arr: [1, 2, 3] };
    const cloned = deepClone(original);
    cloned.arr.push(4);
    t.is(original.arr.length, 3);
});

// === Weather ID Conversion Tests ===
test('convertWeatherIdToLauncherCode maps clear sky (800)', (t) => {
    const result = convertWeatherIdToLauncherCode(800);
    t.is(result, '01');
});

test('convertWeatherIdToLauncherCode maps thunderstorm (200)', (t) => {
    const result = convertWeatherIdToLauncherCode(200);
    t.is(result, '04');
});

test('convertWeatherIdToLauncherCode maps light rain (500)', (t) => {
    const result = convertWeatherIdToLauncherCode(500);
    t.is(result, '08');
});

test('convertWeatherIdToLauncherCode returns 00 for unknown ID', (t) => {
    const originalLog = console.log;
    console.log = () => {};
    const result = convertWeatherIdToLauncherCode(999);
    console.log = originalLog;
    t.is(result, '00');
});

// === Chinese Weather Name Tests ===
test('getChineseWeatherName maps Clear', (t) => {
    const result = getChineseWeatherName('Clear');
    t.is(result, '晴');
});

test('getChineseWeatherName returns original for unknown', (t) => {
    const result = getChineseWeatherName('Unknown');
    t.is(result, 'Unknown');
});

// === AQI Estimation Tests ===
test('estimateAqiFromHumidity returns 50 for low humidity', (t) => {
    const result = estimateAqiFromHumidity(25);
    t.is(result, '50');
});

test('estimateAqiFromHumidity returns 75 for moderate humidity', (t) => {
    const result = estimateAqiFromHumidity(40);
    t.is(result, '75');
});

test('estimateAqiFromHumidity returns 150 for high humidity', (t) => {
    const result = estimateAqiFromHumidity(90);
    t.is(result, '150');
});

// === AQI Level Tests ===
test('getAqiLevel returns value for AQI <= 50', (t) => {
    const result = getAqiLevel(50);
    t.true(result.length > 0);
});

test('getAqiLevel returns different level for AQI > 200', (t) => {
    const result = getAqiLevel(250);
    t.true(result.length > 0);
});

// === PM2.5 Estimation Tests ===
test('estimatePm25FromWeatherData calculates from humidity and pressure', (t) => {
    const result = estimatePm25FromWeatherData({ humidity: 50, pressure: 1013 });
    t.true(parseInt(result) >= 5);
    t.true(parseInt(result) <= 300);
});

test('estimatePm25FromWeatherData handles missing values', (t) => {
    const result = estimatePm25FromWeatherData({});
    t.true(parseInt(result) >= 5);
});

// === Weather Alarm Tests ===
test('getWeatherAlarmKey returns strongWind for high wind speed', (t) => {
    const weatherItem = {
        main: { temp: 20 },
        weather: [{ main: 'Clear' }],
        wind: { speed: 20 },
    };
    const result = getWeatherAlarmKey(weatherItem);
    t.is(result, 'strongWind');
});

test('getWeatherAlarmKey returns null for normal conditions', (t) => {
    const weatherItem = {
        main: { temp: 20 },
        weather: [{ main: 'Clear' }],
        wind: { speed: 5 },
    };
    const result = getWeatherAlarmKey(weatherItem);
    t.is(result, null);
});

test('getWeatherAlarmKey returns highTemp for temperature > 35', (t) => {
    const weatherItem = {
        main: { temp: 40 },
        weather: [{ main: 'Clear' }],
        wind: { speed: 5 },
    };
    const result = getWeatherAlarmKey(weatherItem);
    t.is(result, 'highTemp');
});

test('getWeatherAlarmKey returns lowTemp for temperature < -15', (t) => {
    const weatherItem = {
        main: { temp: -20 },
        weather: [{ main: 'Clear' }],
        wind: { speed: 5 },
    };
    const result = getWeatherAlarmKey(weatherItem);
    t.is(result, 'lowTemp');
});

test('getWeatherAlarmKey returns thunder for Thunderstorm', (t) => {
    const weatherItem = {
        main: { temp: 20 },
        weather: [{ main: 'Thunderstorm' }],
        wind: { speed: 5 },
    };
    const result = getWeatherAlarmKey(weatherItem);
    t.is(result, 'thunder');
});

// === Alarm Level Tests ===
test('getAlarmLevel returns empty for null key', (t) => {
    const result = getAlarmLevel(null);
    t.is(result, '');
});

test('getAlarmLevel returns 黄色 for strongWind', (t) => {
    const result = getAlarmLevel('strongWind');
    t.is(result, '黄色');
});

test('getAlarmLevel returns 橙色 for highTemp', (t) => {
    const result = getAlarmLevel('highTemp');
    t.is(result, '橙色');
});

test('getAlarmLevel returns 蓝色 for lowTemp', (t) => {
    const result = getAlarmLevel('lowTemp');
    t.is(result, '蓝色');
});

// === Alarm Level Code Tests ===
test('getAlarmLevelCode returns 1 for 蓝色', (t) => {
    const result = getAlarmLevelCode('蓝色');
    t.is(result, '1');
});

test('getAlarmLevelCode returns 2 for 黄色', (t) => {
    const result = getAlarmLevelCode('黄色');
    t.is(result, '2');
});

test('getAlarmLevelCode returns empty for unknown level', (t) => {
    const result = getAlarmLevelCode('unknown');
    t.is(result, '');
});

// === Alarm Level English Tests ===
test('getAlarmLevelEn returns Blue for 蓝色', (t) => {
    const result = getAlarmLevelEn('蓝色');
    t.is(result, 'Blue');
});

test('getAlarmLevelEn returns Yellow for 黄色', (t) => {
    const result = getAlarmLevelEn('黄色');
    t.is(result, 'Yellow');
});

// === Alarm Type Tests ===
test('getAlarmType returns 大风 for strongWind', (t) => {
    const result = getAlarmType('strongWind');
    t.is(result, '大风');
});

test('getAlarmType returns 温度 for highTemp', (t) => {
    const result = getAlarmType('highTemp');
    t.is(result, '温度');
});

test('getAlarmType returns empty for null', (t) => {
    const result = getAlarmType(null);
    t.is(result, '');
});

// === Alarm Type English Tests ===
test('getAlarmTypeEn returns Wind for 大风', (t) => {
    const result = getAlarmTypeEn('大风');
    t.is(result, 'Wind');
});

test('getAlarmTypeEn returns Temperature for 温度', (t) => {
    const result = getAlarmTypeEn('温度');
    t.is(result, 'Temperature');
});

// === Admin Code Tests ===
test('getAdminCodeFromCity returns 100000 for CN', (t) => {
    const result = getAdminCodeFromCity({ country: 'CN' });
    t.is(result, '100000');
});

test('getAdminCodeFromCity returns 200000 for RU', (t) => {
    const result = getAdminCodeFromCity({ country: 'RU' });
    t.is(result, '200000');
});

test('getAdminCodeFromCity returns 000000 for unknown', (t) => {
    const result = getAdminCodeFromCity({ country: 'US' });
    t.is(result, '000000');
});
