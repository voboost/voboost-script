/**
 * Rollup plugin to generate multiple log-level variants of each agent
 * Uses AST-based transformation for safe code manipulation
 * Generates: module_0none.js, module_1error.js, module_2info.js, module_3debug.js
 */
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
import { generate } from 'astring';
import { minify } from 'terser';

export function logLevelPlugin() {
    return {
        name: 'log-level-plugin',

        async generateBundle(options, bundle) {
            const processedChunks = new Map();

            // Iterate over all chunks in bundle
            for (const fileName of Object.keys(bundle)) {
                const chunk = bundle[fileName];

                if (chunk.type !== 'chunk') continue;
                if (!fileName.endsWith('.js')) continue;

                const originalCode = chunk.code;

                // Skip empty chunks
                if (!originalCode || originalCode.trim().length === 0) {
                    console.warn(`Skipping empty chunk: ${fileName}`);
                    continue;
                }

                const baseName = fileName.replace('.js', '');

                // Generate variants for different log levels using AST transformation
                // These will be unminified initially
                const variantsUnminified = {
                    none: removeLoggingAST(originalCode, ['error', 'info', 'debug'], true),
                    error: removeLoggingAST(originalCode, ['info', 'debug'], false),
                    info: removeLoggingAST(originalCode, ['debug'], false),
                    debug: originalCode
                };

                // Minify all variants
                const variants = {};
                for (const [level, code] of Object.entries(variantsUnminified)) {
                    if (!code || code.trim().length === 0) {
                        console.warn(`Empty code for ${baseName}_${level}, using original`);
                        variants[level] = originalCode;
                        continue;
                    }

                    try {
                        const result = await minify(code, {
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
                        });

                        if (result && result.code) {
                            variants[level] = result.code;
                        } else {
                            console.warn(`Terser returned empty result for ${baseName}_${level}, using unminified`);
                            variants[level] = code;
                        }
                    } catch (error) {
                        console.error(`Error minifying ${baseName}_${level}:`, error.message);
                        variants[level] = code; // Fallback to unminified
                    }
                }

                // Store processed chunk info
                processedChunks.set(fileName, { baseName, variants });

                // Replace main file with debug version
                chunk.code = variants.debug;
                chunk.fileName = `${baseName}_3debug.js`;
            }

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
 * Remove logging code using AST transformation
 * @param {string} code - Source code
 * @param {string[]} levelsToRemove - Levels to remove ('error', 'info', 'debug')
 * @param {boolean} removeLoggerClass - Whether to remove Logger class and instantiation
 */
function removeLoggingAST(code, levelsToRemove, removeLoggerClass) {
    try {
        const ast = acorn.parse(code, {
            ecmaVersion: 'latest',
            sourceType: 'module'
        });

        // Track nodes to remove by their parent and index
        const nodesToRemove = [];
        let hasLogger = false;

        // Walk the AST and mark nodes for removal
        walk.ancestor(ast, {
            // Find logger method calls: logger.debug(), logger.info(), logger.error()
            ExpressionStatement(node, ancestors) {
                if (node.expression.type === 'CallExpression') {
                    const callExpr = node.expression;
                    if (callExpr.callee.type === 'MemberExpression' &&
                        callExpr.callee.object.type === 'Identifier' &&
                        callExpr.callee.property.type === 'Identifier' &&
                        levelsToRemove.includes(callExpr.callee.property.name)) {
                        hasLogger = true;
                        // Mark the entire expression statement for removal
                        const parent = ancestors[ancestors.length - 2];
                        nodesToRemove.push({ parent, node });
                    }
                }
            },

            // Find Logger class definition (for level 0)
            ClassDeclaration(node, ancestors) {
                if (node.id && node.id.name === 'Logger') {
                    hasLogger = true;
                    if (removeLoggerClass) {
                        const parent = ancestors[ancestors.length - 2];
                        nodesToRemove.push({ parent, node });
                    }
                }
            },

            // Find logger instantiation: const logger = new Logger(...)
            VariableDeclaration(node, ancestors) {
                for (const decl of node.declarations) {
                    if (decl.init?.type === 'NewExpression' &&
                        decl.init.callee.type === 'Identifier' &&
                        decl.init.callee.name === 'Logger') {
                        hasLogger = true;
                        if (removeLoggerClass) {
                            const parent = ancestors[ancestors.length - 2];
                            nodesToRemove.push({ parent, node });
                            break;
                        }
                    }
                }
            }
        });

        // If no logger found, return original code unchanged
        if (!hasLogger) {
            return code;
        }

        // Remove marked nodes from their parents
        for (const { parent, node } of nodesToRemove) {
            if (parent.body && Array.isArray(parent.body)) {
                const index = parent.body.indexOf(node);
                if (index !== -1) {
                    parent.body.splice(index, 1);
                }
            }
        }

        // Generate code from modified AST
        return generate(ast, {
            indent: '',
            lineEnd: '',
            startingIndentLevel: 0
        });
    } catch (error) {
        console.error('AST transformation error:', error.message);
        // Fallback to original code if AST parsing fails
        return code;
    }
}
