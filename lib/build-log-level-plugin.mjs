/**
 * Rollup plugin to generate multiple log-level variants of each agent
 * Generates: module_0none.js, module_1error.js, module_2info.js, module_3debug.js
 */
export function logLevelPlugin() {
    return {
        name: 'log-level-plugin',

        generateBundle(options, bundle) {
            const processedChunks = new Map();

            // Iterate over all chunks in bundle
            Object.keys(bundle).forEach(fileName => {
                const chunk = bundle[fileName];

                if (chunk.type !== 'chunk') return;

                // Process all JavaScript chunks (agent files)
                if (!fileName.endsWith('.js')) return;

                const originalCode = chunk.code;
                const baseName = fileName.replace('.js', '');

                // Generate variants for different log levels
                const variants = {
                    none: removeAllLogging(originalCode),
                    error: removeLogging(originalCode, ['info', 'debug']),
                    info: removeLogging(originalCode, ['debug']),
                    debug: originalCode
                };

                // Store processed chunk info
                processedChunks.set(fileName, { baseName, variants });

                // Replace main file with debug version
                chunk.code = variants.debug;
                chunk.fileName = `${baseName}_3debug.js`;
            });

            // Add other variants as assets
            processedChunks.forEach(({ baseName, variants }) => {
                bundle[`${baseName}_0none.js`] = {
                    type: 'asset',
                    fileName: `${baseName}_0none.js`,
                    source: variants.none
                };

                bundle[`${baseName}_1error.js`] = {
                    type: 'asset',
                    fileName: `${baseName}_1error.js`,
                    source: variants.error
                };

                bundle[`${baseName}_2info.js`] = {
                    type: 'asset',
                    fileName: `${baseName}_2info.js`,
                    source: variants.info
                };
            });
        }
    };
}

/**
 * Remove specific logging levels
 * @param {string} code - Source code
 * @param {string[]} levels - Levels to remove ('error', 'info', 'debug')
 */
function removeLogging(code, levels) {
    let result = code;

    for (const level of levels) {
        // Remove method definitions from Logger class
        result = result.replace(
            new RegExp(`\\s*${level}\\s*\\([^)]*\\)\\s*\\{[^}]*\\}`, 'gs'),
            ''
        );

        // Remove logger method calls - handle both original and minified variable names
        result = result.replace(
            new RegExp(`\\b[a-zA-Z]\\.${level}\\s*\\([^)]*\\)\\s*;?\\s*`, 'gs'),
            ''
        );
    }

    return result;
}

/**
 * Remove all logging code (Logger class and all logger.* calls)
 */
function removeAllLogging(code) {
    let result = code;

    // Remove the entire Logger class block (handle minified class names)
    result = result.replace(
        /class\s+[a-zA-Z]\s*\{[\s\S]*?^\s*}\s*/gm,
        ''
    );

    // Remove logger instantiation (handle minified variable names)
    result = result.replace(
        /const\s+[a-zA-Z]\s*=\s*new\s+[a-zA-Z]\([^)]*\)\s*;?\s*/g,
        ''
    );

    // Use removeLogging to remove all logger method calls
    result = removeLogging(result, ['error', 'info', 'debug']);

    return result;
}
