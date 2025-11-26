import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import terser from '@rollup/plugin-terser';
import fs from 'fs';
import path from 'path';

const OUTPUT_DIR = 'build';

const agentsDir = 'agents';
const files = fs.readdirSync(agentsDir)
    .filter(f => f.endsWith('.js') && f !== 'utils.js')
    .sort();

const configs = files.map(file => {
    const name = path.basename(file, '.js');

    return {
        input: path.join(agentsDir, file),
        output: {
            file: path.join(OUTPUT_DIR, `${name}.js`),
            format: 'iife',
            compact: true,
            sourcemap: false,
        },
        plugins: [
            resolve({
                preferBuiltins: false
            }),
            commonjs(),
            terser({
                compress: {
                    passes: 3,
                    drop_console: false,
                    drop_debugger: true,
                    pure_funcs: [],
                    unsafe: false,
                    unsafe_comps: false,
                    unsafe_math: false,
                    unsafe_proto: false,
                    unsafe_regexp: false,
                    conditionals: true,
                    dead_code: true,
                    evaluate: true,
                    booleans: true,
                    loops: true,
                    unused: true,
                    hoist_funs: true,
                    hoist_props: true,
                    hoist_vars: false,
                    if_return: true,
                    join_vars: true,
                    collapse_vars: true,
                    reduce_vars: true,
                    warnings: false,
                    negate_iife: true,
                    pure_getters: false,
                    keep_fargs: true,
                    keep_fnames: false,
                    keep_infinity: false,
                    side_effects: true
                },
                mangle: {
                    toplevel: false,
                    keep_classnames: false,
                    keep_fnames: false,
                    reserved: ['Java']
                },
                format: {
                    comments: false,
                    beautify: false,
                    ecma: 2015
                }
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
