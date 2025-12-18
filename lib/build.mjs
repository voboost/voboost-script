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

async function buildAll() {
    const configPath = pathToFileURL(path.join(__dirname, '../config/config-rollup.mjs')).href;
    const { default: configs } = await import(configPath);

    if (!fs.existsSync(OUTPUT_DIR)) {
        fs.mkdirSync(OUTPUT_DIR, { recursive: true });
    }

    for (const config of configs) {
        await buildAgent(config);
    }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
    buildAll();
}

export { buildAgent, buildAll };
