export default {
    // Suppress console output during tests unless test fails
    failFast: false,
    // Hide passed tests from output
    verbose: false,
    // Enable worker threads for faster test execution
    workerThreads: true,
    // Suppress console.log and console.warn during tests
    // Only show errors when tests actually fail
    tap: false,
    // Run files in parallel but collect output properly
    concurrency: 512,
    reporter: 'verbose',

    files: ['test/**/*.test.js'],
    // Load test setup files before running tests
    // Order matters: test-logger.js must be first to patch Logger before other mocks
    require: ['./lib/test-logger.js'],

    // Set test environment variables
    environmentVariables: {
        LOG: process.env.LOG || 'error',
        NODE_ENV: 'test',
    },
};
