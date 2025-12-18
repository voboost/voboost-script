import baseConfig from '../../voboost-codestyle/config-eslint.mjs';

export default [
    ...baseConfig,
    // Project-specific overrides
    {
        files: [
            '**/logger.js',
            '**/logger.mjs',
            '**/Logger.js',
            '**/Logger.mjs',
            '**/strip-exports.mjs',
        ],
        rules: {
            'no-console': 'off',
        },
    },
];
