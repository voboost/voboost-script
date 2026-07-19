import { rollup } from 'rollup';
import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const OUTPUT_DIR = 'build';

async function buildAgent(config) {
    const bundle = await rollup(config);
    await bundle.write(config.output);
    await bundle.close();
}

// Remove stale artefacts before each build so old files (renamed/removed
// entries, or leftover `_0none`/`_1error`/... variants from the previous
// multi-variant pipeline) do not linger in build/.
function cleanOutputDir() {
    if (!fs.existsSync(OUTPUT_DIR)) return;
    for (const entry of fs.readdirSync(OUTPUT_DIR)) {
        if (entry.endsWith('.js')) {
            fs.unlinkSync(path.join(OUTPUT_DIR, entry));
        }
    }
}

async function buildAll() {
    const configPath = pathToFileURL(path.join(__dirname, '../config/config-rollup.mjs')).href;
    const { default: configs } = await import(configPath);

    if (!fs.existsSync(OUTPUT_DIR)) {
        fs.mkdirSync(OUTPUT_DIR, { recursive: true });
    } else {
        cleanOutputDir();
    }

    for (const config of configs) {
        await buildAgent(config);
    }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
    buildAll();
}

export { buildAgent, buildAll, cleanOutputDir };
