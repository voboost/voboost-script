const { rollup } = require('rollup');
const fs = require('fs');
const path = require('path');

const OUTPUT_DIR = 'build';

async function buildAgent(config) {
    const bundle = await rollup(config);

    await bundle.write(config.output);
    await bundle.close();
}

async function buildAll() {
    const configPath = path.join(__dirname, '../config/config-rollup.mjs');
    const { default: configs } = await import(configPath);

    if (!fs.existsSync(OUTPUT_DIR)) {
        fs.mkdirSync(OUTPUT_DIR, { recursive: true });
    }

    for (const config of configs) {
        await buildAgent(config);
    }
}

if (require.main === module) {
    buildAll();
}

module.exports = { buildAgent, buildAll };
