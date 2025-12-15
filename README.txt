Используется **Frida** версии **16.2.1**.
Для сборки скриптов используется сборщик, написанный на **Python**. Фактически он может делать импорт из других файлов:

import {
    LANGUAGE_CONFIG_PATH, // константа
    APP_CONFIG_PATH,
    LoadTextFile,         // функция
    parseConfig,
    parseAppConfig
} from './utils.js';

Такая запись позволяет импортировать константы и функции в начало файла.

require('./utils.js');

Эта запись позволяет добавить весь файл.

Для запуска скрипта в **VSCode** вверху, в центре, есть выпадающий список. В нём выбираем **RunTask**, далее ищем «Собрать Frida-агент».
Этот таск можно закрепить или добавить быстрые клавиши. Собираем все скрипты, даже если нет импорта. Это позволит автоматически переместить
скрипт в папку **bundles**. Также при сборке к имени файла добавляется суффикс `-agent`.

---

### Структура папок
- **agents** — исходные скрипты
- **bundles** — итоговые скрипты
- **frida-java-bridge** — мост Java. Для Frida 17+ нужно при сборке добавлять мосты. Сейчас это не используется, так как есть проблемы
 с инжектом в старые версии Android (не удалось запустить).
- **resource** — различные ресурсы, в основном конфиги

---

### Скрипты и команды

- **app-launcher-mod-agent.js** — добавляет сторонние приложения в главный лаунчер и в navbar согласно конфигу.
  frida -U -n com.qinggan.app.launcher -l .\bundles\app-launcher-mod-agent.js

- **app-multi-display-agent.js** — разрешает перемещать приложения между экранами согласно конфигу.
  frida -U -n com.qinggan.systemservice -l .\bundles\app-multi-display-agent.js

- **app-viewport-mod-agent.js** — вписывает и масштабирует приложение согласно конфигу.
  adb shell "pidof system_server"   # получение $PID процесса
  frida -U -p $PID -l .\bundles\app-viewport-mod-agent.js

- **navbar-launcher-mod-gent.js** — управление левым navbar на главном и мультимедийном экране согласно конфигу.
  frida -U -n com.qinggan.app.launcher -l .\bundles\navbar-launcher-mod-agent.js

- **phone_num_mod_agent.js** — исправляет импорт номеров телефонов и звонки.
  adb shell "pidof com.qinggan.bluetoothphone"   # получение $PID процесса
  frida -U -p $PID -l .\bundles\phone-num-mod-agent.js

- **voboost-to-menu-mod-agent.js** — добавляет пункт в меню настроек, позволяет запускать приложение.
  frida -U -n com.qinggan.systemservice -l .\bundles\voboost-to-menu-mod-agent.js

- **weather-widget-mod-agent.js** — исправляет виджет погоды согласно конфигу.
  Требуется регистрация на [openweathermap.org](https://openweathermap.org/) и получение API-ключа.
  frida -U -n com.qinggan.app.launcher -l .\bundles\weather-widget-mod-agent.js

---

### Использование в VSCode

Устанавливал **frida-tools**:
pip install frida-tools==12.4.0
При этом устанавливается **Frida 16.7.19**. Это позволяет работать с **frida-server**.

Необходимо добавить в **PATH** терминала путь к:
LocalCache\local-packages\Python313\Scripts

Пример:
$env:PATH += ";$env:LOCALAPPDATA\Packages\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\LocalCache\local-packages\Python313\Scripts"
Путь может отличаться. Эта настройка работает до перезагрузки терминала, но можно добавить её и на постоянной основе.

---

### Работа с устройством

1. Подключаемся к машине, выполняем `adb root`.
2. Копируем **frida-server**, **frida-inject** и файлы конфигов в папку `/data/local/tmp/test/`.
3. Если установлен **Tweaks** или другие модифицирующие программы, их нужно отключить:
   - Переименовать `load.bin` → `_load.bin`,
   - `frida-inject` → `_frida-inject`.
   - Остановить все инжекты:
     adb shell "pkill -f frida-inject"
   - Остановить приложение:
     adb shell "am force-stop ru.kachalin.voyahtweaks"
4. Запустить сервер:
   adb shell "/data/local/tmp/test/frida-server"
5. Для локального инжекта скопировать скрипты в `/data/local/tmp/test/`.
6. Чтобы вернуть работу **Tweaks**, переименовать файлы обратно и выполнить:
   adb shell "am start -n ru.kachalin.voyahtweaks/.android.activity.main.MainActivity"
7. После этого можно перезагрузить мультимедийный модуль.

### Логирование (Logging)

Логирование выполняется через класс [`Logger`](lib/logger.js:12), который автоматически встраивается в каждый скрипт при сборке через Rollup.

#### Реализация

Логгер находится в [`lib/logger.js`](lib/logger.js:1) и экспортирует класс `Logger` с методами:
- [`error(message)`](lib/logger.js:43) - логирование ошибок с тегом `[-]`
- [`info(message)`](lib/logger.js:51) - логирование важных событий с тегом `[+]`
- [`debug(message)`](lib/logger.js:59) - логирование технических деталей с тегом `[*]`

Все методы автоматически добавляют временную метку в формате `YYYY-MM-DD HH:mm:ss.SSS`, совместимом с Kotlin логгером.

#### Использование

```javascript
// Импортируем Logger из lib/logger.js
import { Logger } from './logger.js';

// Создаём экземпляр логгера с именем модуля
const logger = new Logger('my-agent-name');

// Используем методы логирования
logger.info("Important event happened");
logger.debug("Technical detail for troubleshooting");
logger.error("Something went wrong: " + e.message);
```

#### Запуск через ru.voboost приложение

Приложение ru.voboost запускает Frida скрипты через `FridaManager` и захватывает вывод консоли:

```kotlin
// В ru.voboost приложении
val params = JSONObject().apply {
    put("apiKey", "your-api-key")
}

fridaManager.injectScript(
    targetProcess = "com.qinggan.app.launcher",
    scriptPath = "/data/local/tmp/test/weather-widget-mod-agent.js",
    params = params
)
```

Логи из `console.log()` автоматически сохраняются в `/data/data/ru.voboost/files/voboost-YYYY-MM-DD.log`

#### Ручной запуск через frida (для отладки)

```bash
# Запуск одного агента
frida -U -n com.qinggan.app.launcher \
  -l bundles/weather-widget-mod-agent.js

# Запуск нескольких агентов
frida -U -n com.qinggan.app.launcher \
  -l bundles/weather-widget-mod-agent.js \
  -l bundles/app-launcher-mod-agent.js
```

При ручном запуске логи выводятся в консоль frida.

#### Уровни логирования

| Уровень   | Тег   | Когда использовать                                            | Примеры                                                 |
|-----------|-------|---------------------------------------------------------------|---------------------------------------------------------|
| **info**  | `[+]` | Важные события, которые интересны пользователю/администратору | Запуск агента, действия пользователя, значимые операции |
| **debug** | `[*]` | Технические детали для отладки                                | Вызовы методов, промежуточные значения, проверки        |
| **error** | `[-]` | Ошибки и исключения                                           | Исключения, критические сбои                            |

#### Когда использовать INFO

- Запуск/остановка агента: `"Agent started"`, `"Hooks installed"`
- Действия пользователя: `"App launched: com.example"`, `"Setting changed"`
- Значимые операции: `"Config loaded"`, `"Request proxied"`, `"Icon replaced"`

#### Когда использовать DEBUG

- Вызовы методов: `"getAllApps called for screenId: 0"`
- Итерации и промежуточные значения: `"Processing day: 2024-12-14"`
- Проверки валидации: `"Checking multi-display for: com.example"`
- Ожидаемые случаи (не ошибки): `"App not installed: com.example"` (пропуск, не сбой)

#### Когда использовать ERROR

- Исключения в try/catch: `"Error in hook: " + e.message`
- Критические сбои: `"Failed to load config"`
- Неожиданные состояния: `"System settings button not found"`

#### Файлы логов

- **Расположение:** `/data/data/ru.voboost/files/`
- **Формат имени:** `voboost-YYYY-MM-DD.log`
- **Ротация:** Ежедневно
- **Хранение:** 7 дней

#### Формат логов

Все логи имеют единый формат с временными метками:
```
2024-12-14 14:30:45.123 [+] source: message
2024-12-14 14:30:45.456 [*] source: debug info
2024-12-14 14:30:45.789 [-] source: error message
```

Временные метки генерируются в JS коде и совпадают с форматом Kotlin логгера.
