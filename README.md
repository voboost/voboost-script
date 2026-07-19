# Voboost Scripts

**English** | [Русский](README.ru.md)

Frida agent scripts for the Voboost platform — runtime modifications and
enhancements for the Voyah Android IVI system. Each agent hooks into a
specific system process (launcher, system server, media service, etc.) to
add features, fix bugs, or customize behavior without rebuilding system APKs.

## Relationship to voboost-inject

This repo produces **agent scripts only**. They are not run standalone in
production — they ride inside the [`voboost-inject`](../voboost-inject) daemon:

- The daemon APK (`voboost-inject.apk`) embeds the built agent scripts together
  with a signed `assets/manifest.json` + `assets/manifest.sig` pair.
- `manifest.json` lists every agent with its `id`, `file`, `sha256`, target
  `process`, `kind` (`js` or `native`), and a per-agent `boot` gate.
- On startup, `voboost-inject` verifies `manifest.sig` against its embedded
  public key, then injects each listed agent into its target process via
  `frida-core`, checking the per-file `sha256` before injection.
- Agent updates ship as a new daemon APK through the OTA pipeline (see the
  `ota-core-selfupdate` change in `voboost-inject`); there is no separate
  agent-only update channel.

In short: **agents are developed and tested here, then packaged and signed
inside the voboost-inject daemon APK for deployment.** In production, the
`ru.voboost` app writes an `inject.json` plan that tells the daemon which agents
to enable; it does not inject agents itself.

## Requirements

- **Frida** `16.2.1` on the device (`frida-server` + `frida-inject`)
- **Node.js** for development, build, and tests
- `frida-tools==12.4.0` (installs Frida `16.7.19`, compatible with
  `frida-server`) for local manual injection during development

## Project Structure

| Path | Purpose |
|------|---------|
| [`agents/`](agents) | Agent source scripts (`*-mod.js`) and their log constants (`*-log.js`) |
| [`lib/`](lib) | Shared utilities — [`Logger`](lib/logger.js), [`utils.js`](lib/utils.js), [Rollup build pipeline](lib/build.mjs), [manifest generator](lib/manifest.mjs) |
| [`test/`](test) | AVA test suite — unit tests per agent, build validation, manifest generator tests, logging-pattern compliance |
| [`config/`](config) | Rollup, ESLint, and AVA configuration |
| [`resource/`](resource) | Runtime config files shipped to the device (apps, keyboard, media, weather, etc.) |
| [`build/`](build) | Built agent bundles + `manifest.json` (gitignored; produced by `npm run build`) |

## Commands

```bash
npm install        # Install dependencies (first run)
npm run build      # Bundle all agents into build/ via Rollup
npm test           # Run the full AVA test suite (unit + build validation)
npm run lint        # Fix and format all JS/MJS files with ESLint + Prettier
```

## Agent Scripts

Every agent follows a uniform structure (see [Agent Structure](#agent-structure)
below): a `*-mod.js` implementation paired with a `*-log.js` constants file,
with pure logic extracted into exported, JSDoc-documented functions that are
covered by unit tests in [`test/`](test).

| Agent | Target process | Description |
|-------|----------------|-------------|
| [`adas-activation-mod`](agents/adas-activation-mod.js) | system service | Activates ADAS subscription/NOA learn status |
| [`app-launcher-mod`](agents/app-launcher-mod.js) | `com.qinggan.app.launcher` | Adds third-party apps to the launcher and navbar |
| [`app-multi-display-mod`](agents/app-multi-display-mod.js) | system service | Allows moving apps between screens |
| [`app-viewport-mod`](agents/app-viewport-mod.js) | `system_server` | Scales and positions apps |
| [`forced-ev-mod`](agents/forced-ev-mod.js) | system service | Forces EV mode |
| [`keyboard-lock-en-mod`](agents/keyboard-lock-en-mod.js) | system service | Locks keyboard to English layout |
| [`keyboard-ru-mod`](agents/keyboard-ru-mod.js) | system service | Adds Russian keyboard support |
| [`low-speed-sound-mod`](agents/low-speed-sound-mod.js) | system service | Controls low-speed sound |
| [`media-key-mod`](agents/media-key-mod.js) | media service | Modifies media key handling |
| [`media-source-mod`](agents/media-source-mod.js) | media service | Modifies media sources |
| [`media-window-mod`](agents/media-window-mod.js) | media service | Controls media window behavior |
| [`navbar-launcher-mod`](agents/navbar-launcher-mod.js) | launcher | Controls the left navbar on main and multimedia screens |
| [`phone-num-mod`](agents/phone-num-mod.js) | system service | Fixes phone number imports and calls |
| [`voboost-to-menu-mod`](agents/voboost-to-menu-mod.js) | vehicle settings | Adds a menu item to launch apps (manifest id: `settings-menu`) |
| [`weather-widget-mod`](agents/weather-widget-mod.js) | launcher | Fixes the weather widget (requires an OpenWeatherMap API key) |

## Build System

The project uses [Rollup](https://rollupjs.org/) to bundle each `agents/*-mod.js`
into a single minified IIFE under [`build/`](build). One entry point → one
artefact (`build/<name>.js`). The build also generates `build/manifest.json`
(see [Manifest](#manifest) below).

```bash
npm run build      # bundle every agent + generate build/manifest.json
```

Log level is selected at **runtime** via `setLogLevel()` inside each agent's
entry point. See [`lib/build.mjs`](lib/build.mjs) and
[`config/config-rollup.mjs`](config/config-rollup.mjs).

```javascript
// Inside an agent, ES6 imports are resolved and bundled by Rollup:
import { LANGUAGE_CONFIG_PATH, loadTextFile } from '../lib/utils.js';
```

## Manifest

[`lib/manifest.mjs`](lib/manifest.mjs) generates `build/manifest.json` — the
contract the [`voboost-inject`](../voboost-inject) daemon loads and verifies.
Each agent ships a static metadata block next to its code:

```javascript
// agents/<feature>-mod.js
export const AGENT_META = {
    id: 'weather-widget',                       // daemon agent id
    process: 'com.qinggan.app.launcher',        // target Android process
    boot: false,                                // inject before boot_completed?
};
```

The generator reads every `AGENT_META` (AST-extracted, no `import()` side
effects), hashes each **built** file (`sha256` of the minified bytes), and emits
the daemon schema:

```json
{
  "version": 1,
  "agents": [
    { "id": "...", "channel": "agents", "file": "agents/<source-stem>.js",
      "sha256": "<hex>", "process": "...", "boot": false }
  ]
}
```

The daemon re-verifies each `sha256` before loading an agent
(`voboost-inject/src/frida_controller.vala`), so the manifest is regenerated on
every build — never hand-edited. `id` and `file` are intentionally independent:
`id` matches the app's `FeatureFrida.agentId` vocabulary (so the daemon accepts
the app's `inject.json` plan), while `file` mirrors the source filename
(`agents/voboost-to-menu.js` for `voboost-to-menu-mod.js`) so the on-device path
stays traceable to the source. The APK packaging (done by the `voboost` app)
places `build/<name>-mod.js` at `agents/<name>.js` per the manifest's `file`.

## Usage Examples

```bash
# Launcher agent (manual local inject for development)
frida -U -n com.qinggan.app.launcher -l ./build/app-launcher-mod.js

# System service agent
frida -U -n com.qinggan.systemservice -l ./build/app-multi-display-mod.js

# System server agent (requires PID)
adb shell "pidof system_server"
frida -U -p $PID -l ./build/app-viewport-mod.js

# Multiple agents at once
frida -U -n com.qinggan.app.launcher \
  -l build/weather-widget-mod.js \
  -l build/app-launcher-mod.js
```

## Logging

Logging is handled through the `Logger` class from [`lib/logger.js`](lib/logger.js).
The level is a **process-wide runtime setting** (shared by all `Logger`
instances) — no build-time variants are needed.

### Implementation

The logger exports a `Logger` class plus a `setLogLevel()` / `getLogLevel()`
pair:

- [`setLogLevel('error' | 'info' | 'debug')`](lib/logger.js) — sets the
  threshold. `error` prints only errors; `info` adds info; `debug` adds debug.
  Unknown values fall back to `info`. Default is `info`.
- [`error(message)`](lib/logger.js) — Error logging with `[-]` tag (always
  printed).
- [`info(message)`](lib/logger.js) — Important events logging with `[+]` tag.
- [`debug(message)`](lib/logger.js) — Technical details logging with `[*]` tag.

All methods automatically add timestamps in `YYYY-MM-DD HH:mm:ss.SSS` format,
compatible with the Kotlin logger in the `ru.voboost` app. The log strings
themselves stay defined as constants in `*-log.js` (see
[Agent Structure](#agent-structure)); the level only controls whether a given
call actually emits a line.

### Usage

```javascript
import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './example-log.js';

const logger = new Logger('example-mod');

logger.info(INFO.STARTING);
logger.debug(DEBUG.HOOK_INSTALLED);
logger.error(`${ERROR.HOOK_FAILED} ${e.message}`);
```

### Log Levels

| Level | Tag | When to use | Examples |
|-------|-----|-------------|----------|
| **info** | `[+]` | Important events for user/admin | `STARTING`, `STARTED`, `APP_LAUNCHED` |
| **debug** | `[*]` | Technical details for debugging | `HOOK_INSTALLED`, `CONFIG_LOADED`, `getAllApps called for screenId: 0` |
| **error** | `[-]` | Errors and exceptions | `CONFIG_NOT_AVAILABLE`, `HOOK_FAILED`, `Error in hook: <e.message>` |

### When to use INFO

- Agent lifecycle: `"Agent starting..."`, `"Agent started"`
- User actions: `"App launched: com.example"`, `"Setting changed"`
- Significant operations: `"Config loaded"`, `"Request proxied"`, `"Icon replaced"`

### When to use DEBUG

- Method calls: `"getAllApps called for screenId: 0"`
- Iterations and intermediate values: `"Processing day: 2024-12-14"`
- Validation checks: `"Checking multi-display for: com.example"`
- Expected cases (not errors): `"App not installed: com.example"`

### When to use ERROR

- Exceptions in try/catch: `"Error in hook: " + e.message`
- Critical failures: `"Failed to load config"`
- Unexpected states: `"System settings button not found"`

### Log Files on Device

- **Location:** `/data/data/ru.voboost/files/`
- **Filename format:** `voboost-YYYY-MM-DD.log`
- **Rotation:** Daily
- **Retention:** 7 days

All logs have a unified format with timestamps:

```
2024-12-14 14:30:45.123 [+] source: message
2024-12-14 14:30:45.456 [*] source: debug info
2024-12-14 14:30:45.789 [-] source: error message
```

## Agent Structure

Every agent follows a uniform reference pattern that keeps runtime hooks
separate from testable pure logic. See any `agents/*-mod.js` + `agents/*-log.js`
pair for a real example; the skeleton below illustrates the layout.

### Log File (`*-log.js`)

Every agent has a corresponding log file with named exports by level — no
inline log strings are allowed (enforced by [`test/logging-pattern-compliance.test.js`](test/logging-pattern-compliance.test.js)):

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

```javascript
// agents/example-mod.js
import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './example-log.js';
import { runAgent } from '../lib/utils.js';

const logger = new Logger('example-mod');

/**
 * Pure, testable function with JSDoc.
 * @param {string} input - Description
 * @returns {string} Description
 */
export function pureHelper(input) {
    return input;
}

function someHook() { /* Java.use(...) — not exported */ }

function init() { /* Resolve Java classes */ }

function main() {
    logger.info(INFO.STARTING);
    init();
    someHook();
    logger.info(INFO.STARTED);
}

runAgent(main);
```

### Standards

1. **Consistent lifecycle** — every agent logs `INFO.STARTING` at the start of
   `main()` and `INFO.STARTED` at the end.
2. **Testable pure logic** — decision/mapping helpers are `export`ed with
   JSDoc so they can be unit-tested without a Java/Frida runtime; hooks stay
   private.
3. **Proper categorization** — hook installations go to `DEBUG`, user-visible
   actions to `INFO`, errors and failures to `ERROR`.
4. **No inline log strings** — all log messages are constants from the
   corresponding `*-log.js` file.
5. **Descriptive names** — use clear constant names (`HOOK_INSTALLED`, not
   `HOOK`).
6. **English only** — all source, comments, and docs are ASCII English.

## Code Style

This project follows the unified Voboost code style from
[`voboost-codestyle`](../voboost-codestyle). Rules:

- Line length: 100 characters
- Indentation: 4 spaces
- Quotes: Single quotes
- `console`: only in Logger files

See [voboost-codestyle README](../voboost-codestyle/README.md) for full documentation.

## Development

### VSCode Setup

```bash
pip install frida-tools==12.4.0
```

`frida-tools==12.4.0` installs Frida `16.7.19`, which is compatible with
`frida-server`. Add the frida-tools install dir to `PATH` (on Windows, the
Python Scripts folder under `%LOCALAPPDATA%\Packages\PythonSoftwareFoundation\...`).

### Config File Locations

Agent config files (e.g. `apps-config.json`, `weather-config.json`) can be read from
two distinct on-disk locations. These are not interchangeable:

- **`/data/voboost/agents/config/`** - Production config zone, root-owned
  (mode `0700`, `root:root`). It is provisioned by the `voboost-inject` daemon, which
  writes the current config here before injecting agents, so it is not writable by
  other apps on the device. This is what the path constants in
  [`lib/utils.js`](lib/utils.js) (`LANGUAGE_CONFIG_PATH`, `APP_CONFIG_PATH`,
  `WEATHER_CONFIG_PATH`, etc.) point to, and is used as the on-disk fallback when no
  `parameters.config` / `parameters.configPath` is supplied via `rpc.exports.init()`
  (see [`getConfig()`](lib/utils.js)).
- **`/data/local/tmp/test/`** - Local development/testing path (mode `1777`,
  world-writable) used only when manually copying `frida-server`, `frida-inject`, and
  agent scripts to a device for local injection testing (see "Device Setup" below).
  It is a separate, lower-trust path used purely for local-inject testing and must not
  be used to store or substitute for production agent config.

> **Deployment note.** The on-disk config path is only a fallback; the primary
> production channel is `parameters.config` passed via `rpc.exports.init()`.
> When rolling out updated agents, deploy the `voboost-inject` daemon in lockstep so
> the `/data/voboost/agents/config/` zone is provisioned. An uncoordinated rollout
> (new agents with an older daemon) falls back to `parameters.config` and otherwise
> leaves the agent without config-driven features until the daemon is updated.

### Device Setup

1. Connect to the device and run `adb root`.
2. Copy **frida-server**, **frida-inject**, and config files to
   `/data/local/tmp/test/`.
3. If VoyahTweaks or other modifying programs are installed, disable them:
   - Rename `load.bin` → `_load.bin`
   - Rename `frida-inject` → `_frida-inject`
   - Stop all injects: `adb shell "pkill -f frida-inject"`
   - Stop the app: `adb shell "am force-stop ru.kachalin.voyahtweaks"`
4. Start the server: `adb shell "/data/local/tmp/test/frida-server"`
5. For local inject, copy built scripts to `/data/local/tmp/test/`.
6. To restore Tweaks, rename files back and run:
   `adb shell "am start -n ru.kachalin.voyahtweaks/.android.activity.main.MainActivity"`
7. After restoring Tweaks, restart the multimedia module.

### Testing

Run the full test suite to verify all changes:

```bash
npm test
```

The suite includes unit tests for every agent's exported helpers, build
validation (syntax + minification + manifest regeneration), manifest generator
coverage, and logging-pattern compliance. All tests must pass before merging.

## License

Dual-licensed:

- [PolyForm Noncommercial 1.0.0](https://github.com/voboost/voboost-license/blob/main/LICENSE) — free for personal use
- [Commercial license](https://github.com/voboost/voboost-license/blob/main/COMMERCIAL.md) — required otherwise
