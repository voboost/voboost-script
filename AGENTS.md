# Language & Documentation
- Use English for all code, comments, and documentation
- Keep docs brief and technical (NO EMOJI), in `README.md` only

# Code Style
- Follow JavaScript Style Guide (4-space indent)
- End files with a single empty line
- Run `npm run lint` before commits; never use `eslint-disable`

# Development & Build
- Use NPM scripts exclusively; they should be silent on success
- Use `mv` to move files, not read/write operations
- Use temporary files for complex script validation, not `node -c`

# Commands
- `npm run setup`: Initial project setup
- `npm run build`: Build scripts
- `npm test`: Run test suite

# Project Structure
- Configuration: `config/`
- Code: `agents/`
- Tests: `test/`
- Build: `bundles/`

# Debugging
- When debugging, create backup files with a `.backupN` extension
- Keep backups until the fix is verified, then remove them. Do not edit backups

# Testing
- Tests use AVA, are located in `test/` (`*.test.js`), and run via `npm test`
- All warnings in tests must be fixed
- Test MUST NOT output anything to console in successful pass
