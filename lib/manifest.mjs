/**
 * Manifest generator.
 *
 * Produces `build/manifest.json` for the voboost-inject daemon by combining:
 * - `AGENT_META` exported from each `agents/*-mod.js` source (the single
 *   source of truth for an agent's id, target process, and boot gate);
 * - the sha256 of each **built** file in `build/` (the bytes the daemon will
 *   actually load and verify).
 *
 * AGENT_META is read by AST-parsing the source (acorn), NOT by importing it:
 * importing a `*-mod.js` would execute its top-level `runAgent(main)` call,
 * which tries to start Frida hooks. The object literal is static (string,
 * string, boolean), so AST extraction is reliable and side-effect-free.
 *
 * The manifest schema matches what the daemon parses
 * (`voboost-inject/src/manifest.vala`):
 * ```json
 * {
 *   "version": 1,
 *   "daemon": "<optional daemon version>",
 *   "agents": [
 *     { "id": "...", "channel": "agents", "file": "agents/<id>.js",
 *       "sha256": "<hex>", "process": "...", "boot": false }
 *   ]
 * }
 * ```
 *
 * Required agent fields per daemon: id, file, sha256, process.
 * Optional: channel (defaults to "agents"), boot (defaults to false).
 *
 * Usage as a module: `generateManifest({ buildDir, agentsDir })`.
 * Usage as a script: `node lib/manifest.mjs` (writes build/manifest.json).
 */
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { pathToFileURL } from 'url';
import * as acorn from 'acorn';

// The daemon's manifest_version field. Bumped only on breaking manifest
// schema change. The daemon reads this as `safe_int(obj, "version", 0)`
// and currently treats any value as compatible (it validates field-by-field,
// not by version), so this is informational for now.
export const MANIFEST_VERSION = 1;

// Channel name every agent ships on. The daemon defaults to "agents" when
// the field is absent, and every fixture in voboost-inject uses this value.
export const AGENT_CHANNEL = 'agents';

// Layout convention the daemon expects: files live under `<root_zone>/agents/`
// and the daemon reads `file` as an opaque path (it does NOT derive it from
// `id` — see `voboost-inject/src/frida_controller.vala:404`). The APK
// packaging (done by the `voboost` app) renames `build/<source-basename>.js`
// to `agents/<source-basename-without-mod>.js`, so the manifest's `file`
// field mirrors the source file's basename — keeping the on-device filename
// and the source filename traceable to each other. `id` and `file` are
// independent: an agent can ship under a historical filename while exposing
// an id that matches the app's plan vocabulary.
export function agentFilePath(sourceBasename) {
    // `foo-mod.js` -> `agents/foo.js`; falls back to the input verbatim if the
    // `-mod.js` suffix is absent (so non-conventional sources still work).
    const stem = sourceBasename.replace(/-mod\.js$/, '.js');
    return `agents/${stem}`;
}

// Compute the sha256 hex digest of a file's raw bytes (no trailing NUL —
// matches `trust_store.sha256_file` in the daemon, which uses
// FileUtils.get_data, not get_contents).
export function sha256File(filePath) {
    const data = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(data).digest('hex');
}

// Evaluate a literal AST node (string/boolean/number/null) into its JS value.
// Throws on anything that is not a static literal — AGENT_META values must be
// compile-time constants so the manifest generator never depends on runtime
// state.
function evalLiteral(node, context) {
    switch (node.type) {
        case 'Literal':
            return node.value;
        case 'UnaryExpression':
            if (node.operator === '-' && node.argument.type === 'Literal') {
                return -node.argument.value;
            }
            break;
    }
    throw new Error(`${context}: only static literals (string/number/boolean) are supported`);
}

// Extract the `AGENT_META = { id, process, boot }` object from a parsed
// module's exports. Walks top-level `ExportNamedDeclaration` nodes and finds
// the `AGENT_META` declaration.
export function extractAgentMetaFromAst(ast, sourceFile) {
    for (const node of ast.body) {
        if (node.type !== 'ExportNamedDeclaration') continue;
        const decl = node.declaration;
        if (!decl || decl.type !== 'VariableDeclaration') continue;
        for (const d of decl.declarations) {
            if (d.id.type !== 'Identifier' || d.id.name !== 'AGENT_META') continue;
            if (!d.init || d.init.type !== 'ObjectExpression') {
                throw new Error(`${sourceFile}: AGENT_META must be an object literal`);
            }
            const meta = {};
            for (const prop of d.init.properties) {
                if (prop.type !== 'Property' || prop.key.type !== 'Identifier') continue;
                meta[prop.key.name] = evalLiteral(
                    prop.value,
                    `${sourceFile}: AGENT_META.${prop.key.name}`
                );
            }
            return meta;
        }
    }
    return null;
}

// Parse each `agents/*-mod.js` source with acorn and extract its AGENT_META
// without executing the module (no `runAgent()` side effect).
export function collectAgentMeta(agentsDir) {
    const files = fs
        .readdirSync(agentsDir)
        .filter((f) => f.endsWith('-mod.js'))
        .sort();

    const metas = [];
    for (const file of files) {
        const fullPath = path.resolve(agentsDir, file);
        const code = fs.readFileSync(fullPath, 'utf8');
        const ast = acorn.parse(code, {
            ecmaVersion: 'latest',
            sourceType: 'module',
        });
        const meta = extractAgentMetaFromAst(ast, file);
        if (!meta) {
            throw new Error(`${file} does not export AGENT_META`);
        }
        // Validate required fields up front so a malformed entry fails the
        // build with a clear message instead of producing a manifest the
        // daemon would silently skip (manifest.vala drops agents missing
        // id/file/sha256/process).
        if (!meta.id || typeof meta.id !== 'string') {
            throw new Error(`${file}: AGENT_META.id must be a non-empty string`);
        }
        if (!meta.process || typeof meta.process !== 'string') {
            throw new Error(`${file}: AGENT_META.process must be a non-empty string`);
        }
        if (typeof meta.boot !== 'boolean') {
            throw new Error(`${file}: AGENT_META.boot must be a boolean`);
        }
        metas.push({ file, meta });
    }
    return metas;
}

// Build the manifest object from AGENT_META + sha256 of each built artefact.
// Pure (no I/O — sha256 values are passed in), so it can be unit-tested with
// stubs.
export function buildManifest({ metas, sha256ByModFile, daemonVersion = null }) {
    const seenIds = new Set();
    const agents = metas.map(({ file, meta }) => {
        if (seenIds.has(meta.id)) {
            throw new Error(`duplicate agent id "${meta.id}" (in ${file})`);
        }
        seenIds.add(meta.id);

        const sha256 = sha256ByModFile[file];
        if (!sha256) {
            throw new Error(`no built artefact sha256 for ${file}`);
        }

        const agent = {
            id: meta.id,
            channel: AGENT_CHANNEL,
            file: agentFilePath(file),
            sha256,
            process: meta.process,
            boot: meta.boot,
        };
        return agent;
    });

    const manifest = { version: MANIFEST_VERSION, agents };
    if (daemonVersion) {
        manifest.daemon = daemonVersion;
    }
    return manifest;
}

// Full pipeline: read AGENT_META from sources, hash built files, assemble
// manifest. Returns the manifest object.
export function generateManifest({ buildDir, agentsDir, daemonVersion = null }) {
    const metas = collectAgentMeta(agentsDir);

    // sha256 each built file. The built artefact for `agents/foo-mod.js` is
    // `build/foo-mod.js` (same basename).
    const sha256ByModFile = {};
    for (const { file } of metas) {
        const builtPath = path.resolve(buildDir, file);
        if (!fs.existsSync(builtPath)) {
            throw new Error(`built artefact missing: ${builtPath} (run npm run build)`);
        }
        sha256ByModFile[file] = sha256File(builtPath);
    }

    return buildManifest({ metas, sha256ByModFile, daemonVersion });
}

// Write manifest.json to buildDir. Pretty-printed (2-space) so diffs are
// reviewable; the daemon does not care about whitespace.
export function writeManifest({ buildDir, agentsDir, daemonVersion = null }) {
    const manifest = generateManifest({ buildDir, agentsDir, daemonVersion });
    const outPath = path.resolve(buildDir, 'manifest.json');
    fs.writeFileSync(outPath, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
    return { manifest, outPath };
}

// CLI entry point: generate build/manifest.json.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
    const __dirname = path.dirname(pathToFileURL(import.meta.url).pathname);
    const projectRoot = path.resolve(__dirname, '..');
    const { outPath } = writeManifest({
        buildDir: path.resolve(projectRoot, 'build'),
        agentsDir: path.resolve(projectRoot, 'agents'),
    });
    console.log(`manifest written: ${outPath}`);
}
