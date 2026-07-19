# Voboost Scripts

[English](README.md) | **Русский**

Frida-агенты для платформы Voboost — runtime-модификации и улучшения для Android IVI-системы
Voyah. Каждый агент подключается к конкретному системному процессу (лаунчер, system server,
медиа-сервис и т.д.), чтобы добавить функции, исправить баги или настроить поведение без
пересборки системных APK.

## Связь с voboost-inject

Этот репо выпускает **только скрипты агентов**. В production они не запускаются
самостоятельно — работают внутри демона [`voboost-inject`](../voboost-inject):

- APK демона (`voboost-inject.apk`) встраивает собранные скрипты агентов вместе с парой
  подписанных `assets/manifest.json` + `assets/manifest.sig`.
- `manifest.json` перечисляет каждого агента с его `id`, `file`, `sha256`, целевым
  `process`, `kind` (`js` или `native`) и попрагентным гейтом `boot`.
- При запуске `voboost-inject` проверяет `manifest.sig` против вшитого публичного ключа,
  затем внедряет каждого перечисленного агента в целевой процесс через `frida-core`,
  проверяя `sha256` каждого файла перед внедрением.
- Обновления агентов поставляются как новый APK демона через OTA-конвейер (см. изменение
  `ota-core-selfupdate` в `voboost-inject`); отдельного канала обновления только агентов нет.

Кратко: **агенты разрабатываются и тестируются здесь, затем упаковываются и подписываются
внутри APK демона voboost-inject для развёртывания.** В production приложение `ru.voboost`
пишет план `inject.json`, сообщающий демону каких агентов включить; само оно агентов не внедряет.

## Требования

- **Frida** `16.2.1` на устройстве (`frida-server` + `frida-inject`)
- **Node.js** для разработки, сборки и тестов
- `frida-tools==12.4.0` (устанавливает Frida `16.7.19`, совместимую с
  `frida-server`) для локальной ручной инъекции при разработке

## Структура проекта

| Путь | Назначение |
|------|------------|
| [`agents/`](agents) | Исходные скрипты агентов (`*-mod.js`) и их константы логов (`*-log.js`) |
| [`lib/`](lib) | Общие утилиты — [`Logger`](lib/logger.js), [`utils.js`](lib/utils.js), [пайплайн сборки Rollup](lib/build.mjs), [генератор манифеста](lib/manifest.mjs) |
| [`test/`](test) | Набор тестов AVA — unit-тесты на агента, валидация сборки, соответствие шаблонам логирования |
| [`config/`](config) | Конфигурация Rollup, ESLint и AVA |
| [`resource/`](resource) | Runtime-конфиги, поставляемые на устройство (приложения, клавиатура, медиа, погода и т.д.) |
| [`build/`](build) | Собранные бандлы агентов (gitignored; производятся `npm run build`) |

## Команды

```bash
npm install        # Установить зависимости (первый запуск)
npm run build      # Сбандлить всех агентов в build/ через Rollup
npm test           # Запустить полный набор тестов AVA (unit + валидация сборки)
npm run lint        # Исправить и отформатировать все JS/MJS файлы через ESLint + Prettier
```

## Скрипты агентов

Каждый агент следует единой структуре (см. [Структура агента](#структура-агента) ниже):
реализация `*-mod.js` в паре с файлом констант `*-log.js`, с чистой логикой, извлечённой в
экспортируемые JSDoc-документированные функции, покрытые unit-тестами в [`test/`](test).

| Агент | Целевой процесс | Описание |
|-------|-----------------|----------|
| [`adas-activation-mod`](agents/adas-activation-mod.js) | system service | Активирует подписку ADAS/статус обучения NOA |
| [`app-launcher-mod`](agents/app-launcher-mod.js) | `com.qinggan.app.launcher` | Добавляет сторонние приложения в лаунчер и navbar |
| [`app-multi-display-mod`](agents/app-multi-display-mod.js) | system service | Разрешает перемещение приложений между экранами |
| [`app-viewport-mod`](agents/app-viewport-mod.js) | `system_server` | Масштабирует и позиционирует приложения |
| [`forced-ev-mod`](agents/forced-ev-mod.js) | system service | Принудительно включает EV-режим |
| [`keyboard-lock-en-mod`](agents/keyboard-lock-en-mod.js) | system service | Блокирует клавиатуру на английской раскладке |
| [`keyboard-ru-mod`](agents/keyboard-ru-mod.js) | system service | Добавляет поддержку русской клавиатуры |
| [`low-speed-sound-mod`](agents/low-speed-sound-mod.js) | system service | Управляет звуком на низкой скорости |
| [`media-key-mod`](agents/media-key-mod.js) | media service | Модифицирует обработку медиа-клавиш |
| [`media-source-mod`](agents/media-source-mod.js) | media service | Модифицирует медиа-источники |
| [`media-window-mod`](agents/media-window-mod.js) | media service | Управляет поведением медиа-окна |
| [`navbar-launcher-mod`](agents/navbar-launcher-mod.js) | launcher | Управляет левым navbar на главном и мультимедийном экранах |
| [`phone-num-mod`](agents/phone-num-mod.js) | system service | Исправляет импорт телефонных номеров и звонки |
| [`voboost-to-menu-mod`](agents/voboost-to-menu-mod.js) | vehicle settings | Добавляет пункт меню для запуска приложений (id в манифесте: `settings-menu`) |
| [`weather-widget-mod`](agents/weather-widget-mod.js) | launcher | Чинит виджет погоды (требуется ключ OpenWeatherMap API) |

## Система сборки

Проект использует [Rollup](https://rollupjs.org/) для бандлинга каждого
`agents/*-mod.js` в один минифицированный IIFE в [`build/`](build). Одна точка
входа → один артефакт (`build/<name>.js`). Сборка также генерирует
`build/manifest.json` (см. [Манифест](#манифест) ниже).

```bash
npm run build      # собрать все агенты + сгенерировать build/manifest.json
```

Уровень логирования задаётся **в рантайме** через `setLogLevel()` внутри точки
входа каждого агента. См. [`lib/build.mjs`](lib/build.mjs) и
[`config/config-rollup.mjs`](config/config-rollup.mjs).

```javascript
// Внутри агента ES6-импорты резолвятся и бандлятся Rollup:
import { LANGUAGE_CONFIG_PATH, loadTextFile } from '../lib/utils.js';
```

## Манифест

[`lib/manifest.mjs`](lib/manifest.mjs) генерирует `build/manifest.json` —
контракт, который загружает и проверяет демон
[`voboost-inject`](../voboost-inject). Возле кода каждого агента стоит статический
блок метаданных:

```javascript
// agents/<feature>-mod.js
export const AGENT_META = {
    id: 'weather-widget',                       // id агента в демоне
    process: 'com.qinggan.app.launcher',        // целевой Android-процесс
    boot: false,                                // впрыскивать до boot_completed?
};
```

Генератор читает все `AGENT_META` (AST-извлечение, без побочных эффектов от
`import()`), хеширует каждый **собранный** файл (`sha256` от минифицированных
байт) и эмитит схему демона:

```json
{
  "version": 1,
  "agents": [
    { "id": "...", "channel": "agents", "file": "agents/<имя-исходника>.js",
      "sha256": "<hex>", "process": "...", "boot": false }
  ]
}
```

Демон ре-верифицирует каждый `sha256` перед загрузкой агента
(`voboost-inject/src/frida_controller.vala`), поэтому манифест
перегенерируется на каждой сборке — никогда не редактируется вручную.
`id` и `file` намеренно независимы: `id` совпадает с
`FeatureFrida.agentId` в приложении (чтобы демон принял `inject.json` план),
а `file` повторяет имя исходника (`agents/voboost-to-menu.js` для
`voboost-to-menu-mod.js`) — путь на устройстве остаётся отслеживаемым до
исходника. Упаковка в APK (выполняется приложением `voboost`) кладёт
`build/<name>-mod.js` по пути `agents/<name>.js` согласно `file` манифеста.

## Примеры использования

```bash
# Агент лаунчера (ручная локальная инъекция для разработки)
frida -U -n com.qinggan.app.launcher -l ./build/app-launcher-mod.js

# Агент системного сервиса
frida -U -n com.qinggan.systemservice -l ./build/app-multi-display-mod.js

# Агент system server (требует PID)
adb shell "pidof system_server"
frida -U -p $PID -l ./build/app-viewport-mod.js

# Несколько агентов одновременно
frida -U -n com.qinggan.app.launcher \
  -l build/weather-widget-mod.js \
  -l build/app-launcher-mod.js
```

## Логирование

Логирование идёт через класс `Logger` из [`lib/logger.js`](lib/logger.js).
Уровень — **процесс-глобальная runtime-настройка** (общая для всех инстансов
`Logger`), никаких build-time вариантов не нужно.

### Реализация

Логгер экспортирует класс `Logger` и пару `setLogLevel()` / `getLogLevel()`:

- [`setLogLevel('error' | 'info' | 'debug')`](lib/logger.js) — задаёт порог.
  `error` печатает только ошибки; `info` добавляет info; `debug` добавляет
  debug. Неизвестные значения fallback'ят на `info`. По умолчанию `info`.
- [`error(message)`](lib/logger.js) — Логирование ошибок с тегом `[-]`
  (печатается всегда).
- [`info(message)`](lib/logger.js) — Логирование важных событий с тегом `[+]`.
- [`debug(message)`](lib/logger.js) — Логирование технических деталей с тегом
  `[*]`.

Все методы автоматически добавляют временные метки в формате
`YYYY-MM-DD HH:mm:ss.SSS`, совместимые с Kotlin-логгером в приложении
`ru.voboost`. Сами строки логов остаются константами в `*-log.js`
(см. [Структура агента](#структура-агента)); уровень лишь управляет, будет ли
данный вызов реально выводить строку.

### Использование

```javascript
import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './example-log.js';

const logger = new Logger('example-mod');

logger.info(INFO.STARTING);
logger.debug(DEBUG.HOOK_INSTALLED);
logger.error(`${ERROR.HOOK_FAILED} ${e.message}`);
```

### Уровни логирования

| Уровень | Тег | Когда использовать | Примеры |
|---------|-----|--------------------|---------|
| **info** | `[+]` | Важные события для пользователя/админа | `STARTING`, `STARTED`, `APP_LAUNCHED` |
| **debug** | `[*]` | Технические детали для отладки | `HOOK_INSTALLED`, `CONFIG_LOADED`, `getAllApps called for screenId: 0` |
| **error** | `[-]` | Ошибки и исключения | `CONFIG_NOT_AVAILABLE`, `HOOK_FAILED`, `Error in hook: <e.message>` |

### Когда использовать INFO

- Жизненный цикл агента: `"Agent starting..."`, `"Agent started"`
- Действия пользователя: `"App launched: com.example"`, `"Setting changed"`
- Значимые операции: `"Config loaded"`, `"Request proxied"`, `"Icon replaced"`

### Когда использовать DEBUG

- Вызовы методов: `"getAllApps called for screenId: 0"`
- Итерации и промежуточные значения: `"Processing day: 2024-12-14"`
- Проверки валидации: `"Checking multi-display for: com.example"`
- Ожидаемые случаи (не ошибки): `"App not installed: com.example"`

### Когда использовать ERROR

- Исключения в try/catch: `"Error in hook: " + e.message`
- Критические сбои: `"Failed to load config"`
- Неожиданные состояния: `"System settings button not found"`

### Файлы логов на устройстве

- **Расположение:** `/data/data/ru.voboost/files/`
- **Формат имени:** `voboost-YYYY-MM-DD.log`
- **Ротация:** Ежедневная
- **Хранение:** 7 дней

Все логи имеют единый формат с временными метками:

```
2024-12-14 14:30:45.123 [+] source: message
2024-12-14 14:30:45.456 [*] source: debug info
2024-12-14 14:30:45.789 [-] source: error message
```

## Структура агента

Каждый агент следует единому эталонному шаблону, разделяющему runtime-хуки и тестируемую
чистую логику. См. любую пару `agents/*-mod.js` + `agents/*-log.js` как реальный пример;
скелет ниже иллюстрирует устройство.

### Файл логов (`*-log.js`)

У каждого агента есть соответствующий файл логов с именованными экспортами по уровням —
inline-строки логов запрещены (проверяется
[`test/logging-pattern-compliance.test.js`](test/logging-pattern-compliance.test.js)):

```javascript
// agents/example-log.js
export const INFO = {
    STARTING: 'Agent starting...',
    STARTED: 'Agent started',
    // Agent-specific info messages (user-visible events)
};

export const DEBUG = {
    HOOK_INSTALLED: 'Hooks installed',
    // Agent-specific debug messages (internal operations)
};

export const ERROR = {
    CONFIG_NOT_AVAILABLE: 'Config not available',
    // Agent-specific error messages
};
```

### Файл агента (`*-mod.js`)

```javascript
// agents/example-mod.js
import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './example-log.js';
import { runAgent } from '../lib/utils.js';

const logger = new Logger('example-mod');

/**
 * Чистая тестируемая функция с JSDoc.
 * @param {string} input - Описание
 * @returns {string} Описание
 */
export function pureHelper(input) {
    return input;
}

function someHook() { /* Java.use(...) — не экспортируется */ }

function init() { /* Резолв Java-классов */ }

function main() {
    logger.info(INFO.STARTING);
    init();
    someHook();
    logger.info(INFO.STARTED);
}

runAgent(main);
```

### Стандарты

1. **Единый жизненный цикл** — каждый агент логирует `INFO.STARTING` в начале `main()` и
   `INFO.STARTED` в конце.
2. **Тестируемая чистая логика** — helper'ы принятия решений/маппинга экспортируются с JSDoc,
   чтобы их можно было unit-тестировать без Java/Frida runtime; хуки остаются приватными.
3. **Правильная категоризация** — установка хуков в `DEBUG`, видимые пользователю действия в
   `INFO`, ошибки и сбои в `ERROR`.
4. **Никаких inline-строк логов** — все сообщения логов — константы из соответствующего
   файла `*-log.js`.
5. **Описательные имена** — используйте ясные имена констант (`HOOK_INSTALLED`, не `HOOK`).
6. **Только английский** — все исходники, комментарии и документация — ASCII English.

## Стиль кода

Этот проект следует единому стилю кода Voboost из
[`voboost-codestyle`](../voboost-codestyle). Правила:

- Длина строки: 100 символов
- Отступы: 4 пробела
- Кавычки: Одинарные
- `console`: только в файлах Logger

Полная документация — в [README voboost-codestyle](../voboost-codestyle/README.md).

## Разработка

### Настройка VSCode

```bash
pip install frida-tools==12.4.0
```

`frida-tools==12.4.0` устанавливает Frida `16.7.19`, совместимую с `frida-server`. Добавьте
директорию установки frida-tools в `PATH` (на Windows — папку Python Scripts под
`%LOCALAPPDATA%\Packages\PythonSoftwareFoundation\...`).

### Настройка устройства

1. Подключитесь к устройству и выполните `adb root`.
2. Скопируйте **frida-server**, **frida-inject** и конфиги в `/data/local/tmp/test/`.
3. Если установлены VoyahTweaks или другие модифицирующие программы, отключите их:
   - Переименуйте `load.bin` → `_load.bin`
   - Переименуйте `frida-inject` → `_frida-inject`
   - Остановите все инъекции: `adb shell "pkill -f frida-inject"`
   - Остановите приложение: `adb shell "am force-stop ru.kachalin.voyahtweaks"`
4. Запустите сервер: `adb shell "/data/local/tmp/test/frida-server"`
5. Для локальной инъекции скопируйте собранные скрипты в `/data/local/tmp/test/`.
6. Чтобы восстановить Tweaks, переименуйте файлы обратно и выполните:
   `adb shell "am start -n ru.kachalin.voyahtweaks/.android.activity.main.MainActivity"`
7. После восстановления Tweaks перезапустите мультимедийный модуль.

### Тестирование

Запустите полный набор тестов для проверки всех изменений:

```bash
npm test
```

Набор включает unit-тесты для экспортируемых helper'ов каждого агента, валидацию
сборки (синтаксис + минификация + регенерация манифеста), покрытие генератора
манифеста и соответствие шаблонам логирования. Все тесты должны проходить перед
слиянием.

## Лицензия

Двойная лицензия:

- [PolyForm Noncommercial 1.0.0](https://github.com/voboost/voboost-license/blob/main/LICENSE.ru.md) — бесплатно для личного использования
- [Коммерческая лицензия](https://github.com/voboost/voboost-license/blob/main/COMMERCIAL.ru.md) — требуется для любого коммерческого использования
