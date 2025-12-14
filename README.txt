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
