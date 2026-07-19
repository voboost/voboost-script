/**
 * Build validation tests
 * Verifies that all built files are syntactically valid JavaScript and that
 * every `*-mod.js` entry point in agents/ has exactly one built artefact in
 * build/. The multi-variant (`_0none`/`_1error`/...) pipeline was removed in
 * favour of a runtime log level, so each entry point now maps to a single
 * `build/<name>.js` file.
 */
import test from 'ava';
import fs from 'fs';
import path from 'path';
import vm from 'vm';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BUILD_DIR = path.resolve(__dirname, '../build');
const AGENTS_DIR = path.resolve(__dirname, '../agents');

// Check if build directory exists
if (!fs.existsSync(BUILD_DIR)) {
    process.exit(0);
}

// Get all JavaScript files in build directory
const builtFiles = fs
    .readdirSync(BUILD_DIR)
    .filter((f) => f.endsWith('.js'))
    .sort();

if (builtFiles.length === 0) {
    process.exit(0);
}

// Test each built file for valid JavaScript syntax
for (const file of builtFiles) {
    test(`${file} has valid JavaScript syntax`, (t) => {
        const filePath = path.join(BUILD_DIR, file);
        const code = fs.readFileSync(filePath, 'utf8');

        // Verify file is not empty
        t.truthy(code.length > 0, 'File should not be empty');

        // Verify JavaScript syntax is valid
        t.notThrows(() => {
            new vm.Script(code, { filename: file });
        }, `${file} should have valid JavaScript syntax`);
    });
}

// Every built artefact must be minified: no multi-line pretty-printed code.
// A minified IIFE is a single line (plus maybe a trailing newline). This
// catches accidental regressions where the terser plugin is misconfigured.
test('built files are minified (no pretty-printed multi-line output)', (t) => {
    for (const file of builtFiles) {
        const code = fs.readFileSync(path.join(BUILD_DIR, file), 'utf8');
        const lineCount = code.split('\n').length;
        t.true(lineCount <= 3, `${file} should be minified to ~1 line, got ${lineCount}`);
    }
});

// One entry point in agents/*-mod.js must produce exactly one artefact in
// build/<name>.js, and the artefact set must match the entry set 1:1.
test('build output matches agents/*-mod.js entry points 1:1', (t) => {
    const entryNames = fs
        .readdirSync(AGENTS_DIR)
        .filter((f) => f.endsWith('-mod.js'))
        .map((f) => f.replace(/\.js$/, ''))
        .sort();
    const builtNames = builtFiles.map((f) => f.replace(/\.js$/, '')).sort();

    t.deepEqual(
        builtNames,
        entryNames,
        'build/ should contain exactly one file per agents/*-mod.js entry'
    );
});

// No stale multi-variant artefacts from the old pipeline.
test('no stale _0none/_1error/_2info/_3debug/_minified artefacts remain', (t) => {
    const stale = builtFiles.filter((f) => /_(0none|1error|2info|3debug|minified)\.js$/.test(f));
    t.deepEqual(stale, [], `stale artefacts should be removed: ${stale.join(', ')}`);
});
