import test from 'ava';
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import * as acorn from 'acorn';
import {
    MANIFEST_VERSION,
    AGENT_CHANNEL,
    agentFilePath,
    sha256File,
    extractAgentMetaFromAst,
    collectAgentMeta,
    buildManifest,
    generateManifest,
    writeManifest,
} from '../lib/manifest.mjs';

// === Pure helpers ===

test('agentFilePath: source basename -> agents/<stem>.js (drops -mod suffix)', (t) => {
    // The daemon reads `file` as an opaque path; it does NOT derive it from
    // `id`. The manifest mirrors the source file's basename so the on-device
    // filename stays traceable to the source: `foo-mod.js` -> `agents/foo.js`.
    t.is(agentFilePath('foo-mod.js'), 'agents/foo.js');
    t.is(agentFilePath('app-launcher-mod.js'), 'agents/app-launcher.js');
    t.is(agentFilePath('voboost-to-menu-mod.js'), 'agents/voboost-to-menu.js');
    // Non-conventional sources without `-mod.js` pass through verbatim.
    t.is(agentFilePath('custom.js'), 'agents/custom.js');
});

test('MANIFEST_VERSION is a positive integer', (t) => {
    t.true(Number.isInteger(MANIFEST_VERSION));
    t.true(MANIFEST_VERSION > 0);
});

test('AGENT_CHANNEL is "agents" (daemon default)', (t) => {
    t.is(AGENT_CHANNEL, 'agents');
});

// === sha256File ===

test('sha256File matches manual crypto digest', (t) => {
    const tmp = path.join(os.tmpdir(), `vb-sha256-${Date.now()}.js`);
    const content = 'console.log("hi");';
    fs.writeFileSync(tmp, content);
    const expected = crypto.createHash('sha256').update(content).digest('hex');
    t.is(sha256File(tmp), expected);
    fs.unlinkSync(tmp);
});

test('sha256File is lowercase hex, 64 chars', (t) => {
    const tmp = path.join(os.tmpdir(), `vb-sha256fmt-${Date.now()}.js`);
    fs.writeFileSync(tmp, 'x');
    const hash = sha256File(tmp);
    t.regex(hash, /^[0-9a-f]{64}$/);
    fs.unlinkSync(tmp);
});

// === extractAgentMetaFromAst ===

function parse(source) {
    return acorn.parse(source, { ecmaVersion: 'latest', sourceType: 'module' });
}

test('extractAgentMetaFromAst: reads id/process/boot from object literal', (t) => {
    const ast = parse(`
        export const AGENT_META = {
            id: 'foo',
            process: 'com.example',
            boot: true,
        };
    `);
    const meta = extractAgentMetaFromAst(ast, 'foo.js');
    t.deepEqual(meta, { id: 'foo', process: 'com.example', boot: true });
});

test('extractAgentMetaFromAst: returns null when AGENT_META is absent', (t) => {
    const ast = parse(`export const OTHER = 1;`);
    t.is(extractAgentMetaFromAst(ast, 'foo.js'), null);
});

test('extractAgentMetaFromAst: rejects non-literal values (no runtime state)', (t) => {
    const ast = parse(`
        const proc = 'dynamic';
        export const AGENT_META = { id: 'foo', process: proc, boot: false };
    `);
    t.throws(() => extractAgentMetaFromAst(ast, 'foo.js'), {
        message: /static literals/,
    });
});

test('extractAgentMetaFromAst: rejects non-object literal', (t) => {
    const ast = parse(`export const AGENT_META = 42;`);
    t.throws(() => extractAgentMetaFromAst(ast, 'foo.js'), {
        message: /object literal/,
    });
});

// === buildManifest ===

const sampleMetas = [
    { file: 'foo-mod.js', meta: { id: 'foo', process: 'com.example.a', boot: false } },
    { file: 'bar-mod.js', meta: { id: 'bar', process: 'com.example.b', boot: true } },
];

test('buildManifest: emits one entry per meta with correct schema', (t) => {
    const sha = {
        'foo-mod.js': 'a'.repeat(64),
        'bar-mod.js': 'b'.repeat(64),
    };
    const m = buildManifest({ metas: sampleMetas, sha256ByModFile: sha });
    t.is(m.version, MANIFEST_VERSION);
    t.is(m.agents.length, 2);
    t.deepEqual(m.agents[0], {
        id: 'foo',
        channel: AGENT_CHANNEL,
        file: 'agents/foo.js',
        sha256: 'a'.repeat(64),
        process: 'com.example.a',
        boot: false,
    });
    t.deepEqual(m.agents[1], {
        id: 'bar',
        channel: AGENT_CHANNEL,
        file: 'agents/bar.js',
        sha256: 'b'.repeat(64),
        process: 'com.example.b',
        boot: true,
    });
});

test('buildManifest: includes daemon field only when daemonVersion provided', (t) => {
    const sha = { 'foo-mod.js': 'a'.repeat(64), 'bar-mod.js': 'b'.repeat(64) };
    t.false('daemon' in buildManifest({ metas: sampleMetas, sha256ByModFile: sha }));
    t.is(
        buildManifest({ metas: sampleMetas, sha256ByModFile: sha, daemonVersion: '1.0.0' }).daemon,
        '1.0.0'
    );
});

test('buildManifest: rejects duplicate agent ids', (t) => {
    const metas = [
        { file: 'a-mod.js', meta: { id: 'dup', process: 'p1', boot: false } },
        { file: 'b-mod.js', meta: { id: 'dup', process: 'p2', boot: false } },
    ];
    const sha = { 'a-mod.js': 'a'.repeat(64), 'b-mod.js': 'b'.repeat(64) };
    t.throws(() => buildManifest({ metas, sha256ByModFile: sha }), {
        message: /duplicate agent id "dup"/,
    });
});

test('buildManifest: throws when sha256 missing for a meta', (t) => {
    t.throws(
        () =>
            buildManifest({
                metas: sampleMetas,
                sha256ByModFile: { 'foo-mod.js': 'a'.repeat(64) },
            }),
        { message: /no built artefact sha256 for bar-mod\.js/ }
    );
});

test('buildManifest: id and source filename are independent (file tracks basename, not id)', (t) => {
    // The real-world case this guards: voboost-to-menu-mod.js ships with
    // id="settings-menu" (to match the app plan). The manifest `file` must
    // mirror the source filename, NOT the id, so the daemon's on-disk path
    // stays traceable to the source file.
    const metas = [
        {
            file: 'voboost-to-menu-mod.js',
            meta: { id: 'settings-menu', process: 'p', boot: false },
        },
    ];
    const sha = { 'voboost-to-menu-mod.js': 'a'.repeat(64) };
    const m = buildManifest({ metas, sha256ByModFile: sha });
    t.is(m.agents[0].id, 'settings-menu');
    t.is(m.agents[0].file, 'agents/voboost-to-menu.js');
});

// === generateManifest: end-to-end on a temp project ===

function makeTempProject(agents) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vb-manifest-'));
    const agentsDir = path.join(root, 'agents');
    const buildDir = path.join(root, 'build');
    fs.mkdirSync(agentsDir);
    fs.mkdirSync(buildDir);
    for (const a of agents) {
        const source = `
            export const AGENT_META = {
                id: '${a.id}',
                process: '${a.process}',
                boot: ${a.boot},
            };
        `;
        fs.writeFileSync(path.join(agentsDir, `${a.id}-mod.js`), source);
        // Built artefact: file name matches the source's basename.
        fs.writeFileSync(path.join(buildDir, `${a.id}-mod.js`), a.builtContent || '// built');
    }
    return { root, agentsDir, buildDir };
}

test('generateManifest: end-to-end — sha256 matches built file bytes', (t) => {
    const { agentsDir, buildDir } = makeTempProject([
        { id: 'foo', process: 'com.a', boot: false, builtContent: 'AAA' },
        { id: 'bar', process: 'com.b', boot: true, builtContent: 'BBB' },
    ]);

    const manifest = generateManifest({ buildDir, agentsDir });
    const fooAgent = manifest.agents.find((a) => a.id === 'foo');
    const expectedHash = crypto.createHash('sha256').update('AAA').digest('hex');
    t.is(fooAgent.sha256, expectedHash);
    t.is(fooAgent.process, 'com.a');
    t.is(fooAgent.boot, false);

    const barAgent = manifest.agents.find((a) => a.id === 'bar');
    t.is(barAgent.boot, true);
});

test('generateManifest: throws when built artefact missing', (t) => {
    const { agentsDir, buildDir, root } = makeTempProject([
        { id: 'foo', process: 'com.a', boot: false },
    ]);
    // Delete the built file to simulate stale build/.
    fs.unlinkSync(path.join(buildDir, 'foo-mod.js'));
    t.throws(() => generateManifest({ buildDir, agentsDir }), {
        message: /built artefact missing/,
    });
    fs.rmSync(root, { recursive: true, force: true });
});

test('generateManifest: rejects AGENT_META with non-boolean boot', (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vb-manifest-'));
    const agentsDir = path.join(root, 'agents');
    const buildDir = path.join(root, 'build');
    fs.mkdirSync(agentsDir);
    fs.mkdirSync(buildDir);
    // boot is a string, not a boolean — evalLiteral returns it, but the
    // post-extract validator rejects it.
    fs.writeFileSync(
        path.join(agentsDir, 'foo-mod.js'),
        `export const AGENT_META = { id: 'foo', process: 'p', boot: 'yes' };`
    );
    fs.writeFileSync(path.join(buildDir, 'foo-mod.js'), '// built');
    t.throws(() => generateManifest({ buildDir, agentsDir }), {
        message: /boot must be a boolean/,
    });
    fs.rmSync(root, { recursive: true, force: true });
});

// === writeManifest ===

test('writeManifest: writes valid JSON with trailing newline', (t) => {
    const { agentsDir, buildDir, root } = makeTempProject([
        { id: 'foo', process: 'com.a', boot: false, builtContent: 'X' },
    ]);
    const { outPath } = writeManifest({ buildDir, agentsDir });
    const raw = fs.readFileSync(outPath, 'utf8');
    t.true(raw.endsWith('\n'));
    const parsed = JSON.parse(raw);
    t.is(parsed.version, MANIFEST_VERSION);
    t.is(parsed.agents.length, 1);
    fs.rmSync(root, { recursive: true, force: true });
});

// === Integration against the real repo (skips if no build dir) ===

const __testFilename = fileURLToPath(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(__testFilename), '..');
const REPO_BUILD = path.join(REPO_ROOT, 'build');
const REPO_AGENTS = path.join(REPO_ROOT, 'agents');

if (fs.existsSync(REPO_BUILD) && fs.existsSync(path.join(REPO_BUILD, 'manifest.json'))) {
    test('integration: build/manifest.json matches fresh generation', (t) => {
        const onDisk = JSON.parse(fs.readFileSync(path.join(REPO_BUILD, 'manifest.json'), 'utf8'));
        const fresh = generateManifest({ buildDir: REPO_BUILD, agentsDir: REPO_AGENTS });
        // Re-serialize for stable comparison (key order + formatting).
        t.deepEqual(JSON.parse(JSON.stringify(fresh)), onDisk);
    });

    test('integration: every agent sha256 matches the built file on disk', (t) => {
        const manifest = JSON.parse(
            fs.readFileSync(path.join(REPO_BUILD, 'manifest.json'), 'utf8')
        );
        // The built artefact basename comes from the source filename, NOT
        // from agent.id (those can differ — e.g. voboost-to-menu-mod.js has
        // id="settings-menu"). collectAgentMeta already pairs them, so use
        // it to build id → source-basename and look up the built file from
        // that. This mirrors exactly how the generator picks which file to
        // hash, so the test asserts the same pairing end-to-end.
        const metas = collectAgentMeta(REPO_AGENTS);
        const sourceBasenameById = new Map(metas.map((m) => [m.meta.id, m.file]));
        for (const agent of manifest.agents) {
            const sourceBasename = sourceBasenameById.get(agent.id);
            t.truthy(sourceBasename, `no source file mapped to id ${agent.id}`);
            const builtPath = path.join(REPO_BUILD, sourceBasename);
            t.true(fs.existsSync(builtPath), `${builtPath} should exist`);
            t.is(sha256File(builtPath), agent.sha256, `sha256 for ${agent.id}`);
        }
    });

    test('integration: agent ids are unique', (t) => {
        const manifest = JSON.parse(
            fs.readFileSync(path.join(REPO_BUILD, 'manifest.json'), 'utf8')
        );
        const ids = manifest.agents.map((a) => a.id);
        t.is(new Set(ids).size, ids.length);
    });

    test('integration: every agent has required daemon fields', (t) => {
        const manifest = JSON.parse(
            fs.readFileSync(path.join(REPO_BUILD, 'manifest.json'), 'utf8')
        );
        for (const a of manifest.agents) {
            t.true(typeof a.id === 'string' && a.id.length > 0);
            t.true(typeof a.file === 'string' && a.file.startsWith('agents/'));
            t.regex(a.sha256, /^[0-9a-f]{64}$/);
            t.true(typeof a.process === 'string' && a.process.length > 0);
            t.is(typeof a.boot, 'boolean');
        }
    });
}
