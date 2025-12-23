# Voboost Scripts

Frida scripts for Voyah Android system modification and enhancement.

## Requirements

- **Frida** version **16.2.1**
- Node.js for development and testing

## Project Structure

- **agents** - Source scripts
- **build** - Built scripts
- **lib** - Shared utilities and logger
- **test** - Test suite
- **config** - Configuration files
- **resource** - Various resources, mainly configs

## Build System

The project uses Node.js with Rollup bundler that supports ES6 imports:

```javascript
// Import specific exports
import { LANGUAGE_CONFIG_PATH, LoadTextFile } from './utils.js';

// Include entire file
require('./utils.js');
```

## Commands

```bash
npm run setup    # Initial project setup
npm run build    # Build scripts
npm test         # Run test suite
npm run lint     # Fix all JS/MJS files with ESLint + Prettier
```

## Agent Scripts

- **adas-activation-mod-agent.js** - Controls ADAS activation
- **app-launcher-mod-agent.js** - Adds third-party apps to main launcher and navbar
- **app-multi-display-agent.js** - Allows moving apps between screens
- **app-viewport-mod-agent.js** - Scales and positions apps
- **forced-ev-mod-agent.js** - Forces EV mode
- **keyboard-lock-en-mod-agent.js** - Locks keyboard to English layout
- **keyboard-ru-mod-agent.js** - Adds Russian keyboard support
- **low-speed-sound-mod-agent.js** - Controls low speed sound
- **media-source-mod-agent.js** - Modifies media sources
- **media-window-mod-agent.js** - Controls media window behavior
- **navbar-launcher-mod-agent.js** - Controls left navbar on main and multimedia screens
- **phone-num-mod-agent.js** - Fixes phone number imports and calls
- **voboost-to-menu-mod-agent.js** - Adds menu item to launch apps
- **weather-widget-mod-agent.js** - Fixes weather widget (requires OpenWeatherMap API key)

## Usage Examples

```bash
# Launcher agent
frida -U -n com.qinggan.app.launcher -l ./build/app-launcher-mod.js

# System service agent
frida -U -n com.qinggan.systemservice -l ./build/app-multi-display.js

# System server agent (requires PID)
adb shell "pidof system_server"
frida -U -p $PID -l ./build/app-viewport-mod.js

# Multiple agents at once
frida -U -n com.qinggan.app.launcher \
  -l build/weather-widget-mod.js \
  -l build/app-launcher-mod.js
```

## Logging

Logging is handled through the `Logger` class from [`lib/logger.js`](lib/logger.js), which is automatically integrated into each script during the build process.

### Implementation

The logger is located in [`lib/logger.js`](lib/logger.js:1) and exports a `Logger` class with methods:
- [`error(message)`](lib/logger.js:43) - Error logging with `[-]` tag
- [`info(message)`](lib/logger.js:51) - Important events logging with `[+]` tag
- [`debug(message)`](lib/logger.js:59) - Technical details logging with `[*]` tag

All methods automatically add timestamps in `YYYY-MM-DD HH:mm:ss.SSS` format, compatible with Kotlin logger.

### Usage

```javascript
// Import Logger from lib/logger.js
import { Logger } from './logger.js';

// Create logger instance with module name
const logger = new Logger('my-agent-name');

// Use logging methods
logger.info("Important event happened");
logger.debug("Technical detail for troubleshooting");
logger.error("Something went wrong: " + e.message);
```

### Log Levels

| Level   | Tag   | When to use                                              | Examples                                    |
|---------|-------|----------------------------------------------------------|---------------------------------------------|
| **info**  | `[+]` | Important events for user/admin                          | Agent start, user actions, significant ops  |
| **debug** | `[*]` | Technical details for debugging                          | Method calls, intermediate values, checks   |
| **error** | `[-]` | Errors and exceptions                                     | Exceptions, critical failures               |

### When to Use INFO

- Agent lifecycle: `"Agent started"`, `"Hooks installed"`
- User actions: `"App launched: com.example"`, `"Setting changed"`
- Significant operations: `"Config loaded"`, `"Request proxied"`, `"Icon replaced"`

### When to Use DEBUG

- Method calls: `"getAllApps called for screenId: 0"`
- Iterations and intermediate values: `"Processing day: 2024-12-14"`
- Validation checks: `"Checking multi-display for: com.example"`
- Expected cases (not errors): `"App not installed: com.example"`

### When to Use ERROR

- Exceptions in try/catch: `"Error in hook: " + e.message`
- Critical failures: `"Failed to load config"`
- Unexpected states: `"System settings button not found"`

### Running via ru.voboost App

The ru.voboost app launches Frida scripts via `FridaManager`:

```kotlin
val params = JSONObject().apply {
    put("apiKey", "your-api-key")
}

fridaManager.injectScript(
    targetProcess = "com.qinggan.app.launcher",
    scriptPath = "/data/local/tmp/test/weather-widget-mod-agent.js",
    params = params
)
```

Logs from `console.log()` are saved to `/data/data/ru.voboost/files/voboost-YYYY-MM-DD.log`

### Log Files

- **Location:** `/data/data/ru.voboost/files/`
- **Filename format:** `voboost-YYYY-MM-DD.log`
- **Rotation:** Daily
- **Retention:** 7 days

### Log Format

All logs have unified format with timestamps:
```
2024-12-14 14:30:45.123 [+] source: message
2024-12-14 14:30:45.456 [*] source: debug info
2024-12-14 14:30:45.789 [-] source: error message
```

Timestamps are generated in JS code and match Kotlin logger format.

## Agent Structure

### Log File (`*-log.js`)

Every agent must have a corresponding log file with named exports by level:

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

### Agent File (`*-mod.js`)

Standard agent structure:

```javascript
// agents/example-mod.js
import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './example-log.js';
import { runAgent } from '../lib/utils.js';

const logger = new Logger('example-mod');

function main() {
    logger.info(INFO.STARTING);

    // ... agent initialization ...

    logger.info(INFO.STARTED);
}

runAgent(main);
```

### Log Level Guidelines

| Level | When to Use | Examples |
|-------|-------------|----------|
| **INFO** | Agent lifecycle, important user-visible events | `STARTING`, `STARTED`, `APP_LAUNCHED` |
| **DEBUG** | Internal operations, hook installations, technical details | `HOOK_INSTALLED`, `CONFIG_LOADED` |
| **ERROR** | Failures, exceptions, missing required config | `CONFIG_NOT_AVAILABLE`, `HOOK_FAILED` |

### Log Message Standards

1. **Consistent lifecycle**: Every agent must log `INFO.STARTING` at the beginning and `INFO.STARTED` at the end of `main()`
2. **Proper categorization**:
   - Hook installations go to `DEBUG`
   - User-visible actions go to `INFO`
   - Errors and failures go to `ERROR`
3. **No inline strings**: All log messages must be constants from the corresponding `-log.js` file
4. **Descriptive names**: Use clear, descriptive constant names (e.g., `HOOK_INSTALLED` not `HOOK`)

### Import Patterns

```javascript
import { INFO, DEBUG, ERROR } from './agent-log.js';
```

### Usage Examples

```javascript
// Agent lifecycle
logger.info(INFO.STARTING);
logger.info(INFO.STARTED);

// Internal operations
logger.debug(DEBUG.HOOK_INSTALLED);
logger.debug(DEBUG.CONFIG_LOADED);

// User-visible events
logger.info(INFO.APP_LAUNCHED);
logger.info(INFO.BUTTON_ADDED);

// Errors
logger.error(ERROR.CONFIG_NOT_AVAILABLE);
logger.error(`${ERROR.HOOK_FAILED} ${e.message}`);
```

## Code Style

This project follows the unified Voboost code style from [voboost-codestyle](../voboost-codestyle).

### Rules

- Line length: 100 characters
- Indentation: 4 spaces
- Quotes: Single quotes
- Console: Only allowed in Logger files

See [voboost-codestyle README](../voboost-codestyle/README.md) for full documentation.

## Development

### VSCode Setup

Install frida-tools:
```bash
pip install frida-tools==12.4.0
```

Note: `frida-tools==12.4.0` installs Frida 16.7.19, which is compatible with frida-server.

Add to PATH (example for Windows):
```powershell
$env:PATH += ";$env:LOCALAPPDATA\Packages\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\LocalCache\local-packages\Python313\Scripts"
```

### Device Setup

1. Connect to device and run `adb root`
2. Copy **frida-server**, **frida-inject** and config files to `/data/local/tmp/test/`
3. If VoyahTweaks or other modifying programs are installed, disable them:
   - Rename `load.bin` → `_load.bin`
   - Rename `frida-inject` → `_frida-inject`
   - Stop all injects: `adb shell "pkill -f frida-inject"`
   - Stop app: `adb shell "am force-stop ru.kachalin.voyahtweaks"`
4. Start server: `adb shell "/data/local/tmp/test/frida-server"`
5. For local inject, copy scripts to `/data/local/tmp/test/`
6. To restore Tweaks, rename files back and run:
   `adb shell "am start -n ru.kachalin.voyahtweaks/.android.activity.main.MainActivity"`
7. After restoring Tweaks, you can restart the multimedia module

### Testing

Run the test suite to verify all changes work correctly:
```bash
npm test
```

All tests should pass, including unit tests, build validation, and syntax checks.
