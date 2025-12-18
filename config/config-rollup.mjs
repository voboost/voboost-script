import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import { logLevelPlugin } from '../lib/build-log-level-plugin.mjs';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const OUTPUT_DIR = path.resolve(__dirname, '../build');
const agentsDir = path.resolve(__dirname, '../agents');

if (!fs.existsSync(agentsDir)) {
    console.error(`Directory ${agentsDir} does not exist!`);
    process.exit(1);
}

const files = fs
    .readdirSync(agentsDir)
    .filter((f) => f.endsWith('.js'))
    .sort();

// Check if minification should be disabled
const shouldMinify = process.env.MINIFY !== 'false';

const configs = files.flatMap((file) => {
    const name = path.basename(file, '.js');
    const inputPath = path.resolve(agentsDir, file);

    const baseConfig = {
        input: inputPath,
        plugins: [resolve({ preferBuiltins: false }), commonjs()],
        treeshake: {
            moduleSideEffects: true,
            propertyReadSideEffects: true,
            tryCatchDeoptimization: true,
            unknownGlobalSideEffects: true,
        },
        onwarn: (warning, warn) => {
            if (warning.code === 'CIRCULAR_DEPENDENCY') return;
            if (warning.code === 'EVAL') return;
            if (warning.code === 'MISSING_NAME_OPTION_FOR_IIFE_EXPORT') return;
            warn(warning);
        },
    };

    const outputs = [];

    // Unminified debug output (always generated)
    outputs.push({
        ...baseConfig,
        output: {
            file: path.resolve(OUTPUT_DIR, `${name}.js`),
            format: 'iife',
            compact: false,
            sourcemap: false,
        },
    });

    // Minified outputs with log-level variants (only if minification is enabled)
    if (shouldMinify) {
        outputs.push({
            ...baseConfig,
            output: {
                file: path.resolve(OUTPUT_DIR, `${name}_minified.js`),
                format: 'iife',
                compact: true,
                sourcemap: false,
            },
            plugins: [...baseConfig.plugins, logLevelPlugin()],
        });
    }

    return outputs;
});

export default configs;
