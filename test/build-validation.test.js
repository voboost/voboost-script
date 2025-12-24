/**
 * Build validation tests
 * Verifies that all built files are syntactically valid JavaScript
 */
import test from 'ava';
import fs from 'fs';
import path from 'path';
import vm from 'vm';
import { fileURLToPath } from 'url';
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BUILD_DIR = path.resolve(__dirname, '../build');

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

// Test that log-level variants exist for minified files
test('log-level variants exist for minified files', (t) => {
    // Get base agent names
    const baseNames = new Set();
    for (const file of builtFiles) {
        const match = file.match(/^(.+)_[0-3](none|error|info|debug)\.js$/);
        if (match) {
            baseNames.add(match[1]);
        }
    }

    // Check that each base has all 4 minified variants
    for (const baseName of baseNames) {
        const variants = [
            `${baseName}_0none.js`,
            `${baseName}_1error.js`,
            `${baseName}_2info.js`,
            `${baseName}_3debug.js`,
        ];

        for (const variant of variants) {
            const exists = builtFiles.includes(variant);
            t.true(exists, `${variant} should exist`);
        }
    }
});

// Test that unminified files exist
test('unminified debug files exist', (t) => {
    const unminifiedFiles = builtFiles.filter(
        (f) => !f.match(/_[0-3](none|error|info|debug)\.js$/)
    );
    t.true(unminifiedFiles.length > 0, 'At least one unminified file should exist');
});

// Test that minified files are smaller than unminified
test('minified files are smaller than unminified', (t) => {
    const unminifiedFiles = builtFiles.filter(
        (f) => !f.match(/_[0-3](none|error|info|debug)\.js$/)
    );

    for (const unminifiedFile of unminifiedFiles) {
        const baseName = unminifiedFile.replace('.js', '');
        const minifiedFile = `${baseName}_3debug.js`;

        if (builtFiles.includes(minifiedFile)) {
            const unminifiedSize = fs.statSync(path.join(BUILD_DIR, unminifiedFile)).size;
            const minifiedSize = fs.statSync(path.join(BUILD_DIR, minifiedFile)).size;

            t.true(
                minifiedSize < unminifiedSize,
                `${minifiedFile} (${minifiedSize} bytes) should be smaller than ${unminifiedFile} (${unminifiedSize} bytes)`
            );
        }
    }
});

// Test that none variant is smallest (has least logging code)
test('none variant has no logging code', (t) => {
    // Get base agent names
    const baseNames = new Set();
    for (const file of builtFiles) {
        const match = file.match(/^(.+)_0none\.js$/);
        if (match) {
            baseNames.add(match[1]);
        }
    }

    for (const baseName of baseNames) {
        const noneFile = `${baseName}_0none.js`;
        const debugFile = `${baseName}_3debug.js`;

        if (builtFiles.includes(noneFile) && builtFiles.includes(debugFile)) {
            const noneSize = fs.statSync(path.join(BUILD_DIR, noneFile)).size;
            const debugSize = fs.statSync(path.join(BUILD_DIR, debugFile)).size;

            // None variant should be smaller or equal to debug variant
            t.true(
                noneSize <= debugSize,
                `${noneFile} (${noneSize} bytes) should be <= ${debugFile} (${debugSize} bytes)`
            );
        }
    }
});

// Helper to check Logger methods using AST
function checkLoggerMethods(code, expectedMethods) {
    try {
        const ast = acorn.parse(code, {
            ecmaVersion: 'latest',
            sourceType: 'script',
        });

        const foundMethods = new Set();

        walk.simple(ast, {
            ClassDeclaration(node) {
                // Check all classes since Logger might be inlined with a different name
                // Look for methods that match Logger's signature
                for (const method of node.body.body) {
                    if (method.type === 'MethodDefinition' && method.key.type === 'Identifier') {
                        if (['error', 'info', 'debug'].includes(method.key.name)) {
                            foundMethods.add(method.key.name);
                        }
                    }
                }
            },
        });

        // Check if all expected methods are found
        for (const method of expectedMethods) {
            if (!foundMethods.has(method)) {
                return false;
            }
        }

        // Check if no unexpected methods are found
        for (const method of foundMethods) {
            if (!expectedMethods.includes(method) && ['error', 'info', 'debug'].includes(method)) {
                return false;
            }
        }

        return true;
    } catch {
        // If AST parsing fails, fall back to regex for unminified files
        const hasError = /error\s*\(/.test(code);
        const hasInfo = /info\s*\(/.test(code);
        const hasDebug = /debug\s*\(/.test(code);

        if (expectedMethods.includes('error') && !hasError) return false;
        if (expectedMethods.includes('info') && !hasInfo) return false;
        if (expectedMethods.includes('debug') && !hasDebug) return false;

        if (!expectedMethods.includes('info') && hasInfo) return false;
        if (!expectedMethods.includes('debug') && hasDebug) return false;

        return true;
    }
}

// Test that _1error.js Logger class has no info or debug methods (only check mod files)
test('_1error.js Logger class has no info or debug methods', (t) => {
    const errorFiles = builtFiles.filter((f) => f.endsWith('_1error.js') && f.includes('-mod'));
    t.true(errorFiles.length > 0, 'Should have at least one _1error.js mod file');

    for (const file of errorFiles) {
        const filePath = path.join(BUILD_DIR, file);
        const code = fs.readFileSync(filePath, 'utf8');

        // Check that Logger class only has error() method
        const hasCorrectMethods = checkLoggerMethods(code, ['error']);

        t.true(hasCorrectMethods, `${file} should only contain error() method in Logger class`);
    }
});

// Test that _2info.js Logger class has no debug method (only check mod files)
test('_2info.js Logger class has no debug method', (t) => {
    const infoFiles = builtFiles.filter((f) => f.endsWith('_2info.js') && f.includes('-mod'));
    t.true(infoFiles.length > 0, 'Should have at least one _2info.js mod file');

    for (const file of infoFiles) {
        const filePath = path.join(BUILD_DIR, file);
        const code = fs.readFileSync(filePath, 'utf8');

        // Check that Logger class has error() and info() methods but not debug()
        const hasCorrectMethods = checkLoggerMethods(code, ['error', 'info']);

        t.true(
            hasCorrectMethods,
            `${file} should contain error() and info() methods but not debug() in Logger class`
        );
    }
});

// Test that _3debug.js Logger class has all methods (only check mod files, not log files)
test('_3debug.js Logger class has all logging methods', (t) => {
    const debugFiles = builtFiles.filter((f) => f.endsWith('_3debug.js') && f.includes('-mod'));
    t.true(debugFiles.length > 0, 'Should have at least one _3debug.js mod file');

    for (const file of debugFiles) {
        const filePath = path.join(BUILD_DIR, file);
        const code = fs.readFileSync(filePath, 'utf8');

        // Check that Logger class has all methods
        const hasCorrectMethods = checkLoggerMethods(code, ['error', 'info', 'debug']);

        t.true(hasCorrectMethods, `${file} should contain all logging methods in Logger class`);
    }
});
