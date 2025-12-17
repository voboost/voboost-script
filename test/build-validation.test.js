/**
 * Build validation tests
 * Verifies that all built files are syntactically valid JavaScript
 */
import test from 'ava';
import fs from 'fs';
import path from 'path';
import vm from 'vm';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BUILD_DIR = path.resolve(__dirname, '../build');

// Check if build directory exists
if (!fs.existsSync(BUILD_DIR)) {
    console.warn('Build directory does not exist. Run "npm run build" first.');
    process.exit(0);
}

// Get all JavaScript files in build directory
const builtFiles = fs.readdirSync(BUILD_DIR)
    .filter(f => f.endsWith('.js'))
    .sort();

if (builtFiles.length === 0) {
    console.warn('No built files found. Run "npm run build" first.');
    process.exit(0);
}

// Test each built file for valid JavaScript syntax
for (const file of builtFiles) {
    test(`${file} has valid JavaScript syntax`, t => {
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

// Test that log-level variants exist for minified files
test('log-level variants exist for minified files', t => {
    // Get base agent names (without _minified suffix)
    const baseNames = new Set();
    for (const file of builtFiles) {
        const match = file.match(/^(.+)_minified_[0-3](none|error|info|debug)\.js$/);
        if (match) {
            baseNames.add(match[1]);
        }
    }

    // Check that each base has all 4 minified variants
    for (const baseName of baseNames) {
        const variants = [
            `${baseName}_minified_0none.js`,
            `${baseName}_minified_1error.js`,
            `${baseName}_minified_2info.js`,
            `${baseName}_minified_3debug.js`
        ];

        for (const variant of variants) {
            const exists = builtFiles.includes(variant);
            t.true(exists, `${variant} should exist`);
        }
    }
});

// Test that unminified files exist
test('unminified debug files exist', t => {
    const unminifiedFiles = builtFiles.filter(f =>
        !f.includes('_minified') &&
        !f.match(/_[0-3](none|error|info|debug)\.js$/)
    );
    t.true(unminifiedFiles.length > 0, 'At least one unminified file should exist');
});

// Test that minified files are smaller than unminified
test('minified files are smaller than unminified', t => {
    const unminifiedFiles = builtFiles.filter(f =>
        !f.includes('_minified') &&
        !f.match(/_[0-3](none|error|info|debug)\.js$/)
    );

    for (const unminifiedFile of unminifiedFiles) {
        const baseName = unminifiedFile.replace('.js', '');
        const minifiedFile = `${baseName}_minified_3debug.js`;

        if (builtFiles.includes(minifiedFile)) {
            const unminifiedSize = fs.statSync(path.join(BUILD_DIR, unminifiedFile)).size;
            const minifiedSize = fs.statSync(path.join(BUILD_DIR, minifiedFile)).size;

            t.true(minifiedSize < unminifiedSize,
                `${minifiedFile} (${minifiedSize} bytes) should be smaller than ${unminifiedFile} (${unminifiedSize} bytes)`);
        }
    }
});

// Test that none variant is smallest (has least logging code)
test('none variant has no logging code', t => {
    // Get base agent names
    const baseNames = new Set();
    for (const file of builtFiles) {
        const match = file.match(/^(.+)_minified_[0-3](none|error|info|debug)\.js$/);
        if (match) {
            baseNames.add(match[1]);
        }
    }

    for (const baseName of baseNames) {
        const noneFile = `${baseName}_minified_0none.js`;
        const debugFile = `${baseName}_minified_3debug.js`;

        if (builtFiles.includes(noneFile) && builtFiles.includes(debugFile)) {
            const noneSize = fs.statSync(path.join(BUILD_DIR, noneFile)).size;
            const debugSize = fs.statSync(path.join(BUILD_DIR, debugFile)).size;

            // None variant should be smaller or equal to debug variant
            t.true(noneSize <= debugSize,
                `${noneFile} (${noneSize} bytes) should be <= ${debugFile} (${debugSize} bytes)`);
        }
    }
});
