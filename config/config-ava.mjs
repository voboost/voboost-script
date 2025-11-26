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
    // Only show test failures
    reporter: 'verbose',

    files: [
        'test/**/*.test.js',
    ]
};
