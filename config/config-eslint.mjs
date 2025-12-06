import js from '@eslint/js';
import globals from 'globals';

export default [
    js.configs.recommended,

    {
        // Global configuration
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'module',
            globals: {
                console: 'readonly',
                Java: 'readonly',
                module: 'readonly',
                setTimeout: 'readonly',
                clearTimeout: 'readonly',
                setInterval: 'readonly',
                clearInterval: 'readonly',
            },
        },

        rules: {
            'indent': ['error', 4], // 4 spaces
            'brace-style': ['error', '1tbs', { 'allowSingleLine': true }], // brace on same line
            'max-len': ['error', {
                'code': 140, // 140 char line length
            }],
            'comma-dangle': ['error', 'always-multiline'], // trailing commas
            'function-paren-newline': ['error', 'multiline-arguments'], // multiline args
            'function-call-argument-newline': ['error', 'consistent'], // consistent line breaks in args

            // Essential rules from recommended
            'no-console': 'off',      // allow console in build scripts

            'quotes': ['error', 'double'],
            'semi': ['error', 'always'],
            'eol-last': 'error',
            'no-trailing-spaces': 'error',
        },
    },

    {
        ignores: [
            '.build/**',
            'config/**',
        ],
    },
];
