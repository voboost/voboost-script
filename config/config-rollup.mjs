import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import terser from '@rollup/plugin-terser';
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

const files = fs.readdirSync(agentsDir)
  .filter(f => f.endsWith('.js') && f !== 'utils.js')
  .sort();

const configs = files.map(file => {
  const name = path.basename(file, '.js');
  const inputPath = path.resolve(agentsDir, file);

  return {
    input: inputPath,
    output: {
      file: path.resolve(OUTPUT_DIR, `${name}.js`),
      format: 'iife',
      compact: true,
      sourcemap: false,
    },
    plugins: [
      resolve({ preferBuiltins: false }),
      commonjs(),
      terser({
        compress: {
          passes: 3,
          drop_console: false,
          drop_debugger: true,
          conditionals: true,
          dead_code: true,
          evaluate: true,
          booleans: true,
          loops: true,
          unused: true,
          hoist_funs: true,
          hoist_props: true,
          if_return: true,
          join_vars: true,
          collapse_vars: true,
          reduce_vars: true,
          warnings: false,
          negate_iife: true,
          keep_fargs: true,
          side_effects: true
        },
        mangle: { reserved: ['Java'] },
        format: { comments: false, beautify: false, ecma: 2015 }
      })
    ],
    treeshake: {
      moduleSideEffects: true,
      propertyReadSideEffects: true,
      tryCatchDeoptimization: true,
      unknownGlobalSideEffects: true
    },
    onwarn: (warning, warn) => {
      if (warning.code === 'CIRCULAR_DEPENDENCY') return;
      if (warning.code === 'EVAL') return;
      warn(warning);
    }
  };
});

export default configs;