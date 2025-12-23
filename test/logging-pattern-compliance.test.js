import test from 'ava';
import { readFileSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';

const __dirname = dirname(fileURLToPath(import.meta.url));
const agentsDir = join(__dirname, '../agents');

const AGENT_FILES = readdirSync(agentsDir).filter((f) => f.endsWith('-mod.js'));

/**
 * Check if AST node is a logger call: logger.{method}({obj}.{prop})
 */
function isLoggerCall(node, method, obj, prop) {
    if (node?.type !== 'ExpressionStatement') return false;
    const expr = node.expression;
    if (expr?.type !== 'CallExpression') return false;
    if (expr.callee?.type !== 'MemberExpression') return false;
    if (expr.callee.object?.name !== 'logger') return false;
    if (expr.callee.property?.name !== method) return false;
    if (expr.arguments?.length !== 1) return false;
    const arg = expr.arguments[0];
    if (arg?.type !== 'MemberExpression') return false;
    if (arg.object?.name !== obj) return false;
    if (arg.property?.name !== prop) return false;
    return true;
}

/**
 * Find main() function in AST
 */
function findMainFunction(ast) {
    let mainFunction = null;

    walk.simple(ast, {
        FunctionDeclaration(node) {
            if (node.id?.name === 'main') {
                mainFunction = node;
            }
        },
    });

    return mainFunction;
}

// Test each agent file
for (const filename of AGENT_FILES) {
    test(`${filename} main() logging pattern`, (t) => {
        const filePath = join(agentsDir, filename);
        const code = readFileSync(filePath, 'utf8');

        // Parse with acorn
        const ast = acorn.parse(code, {
            ecmaVersion: 2022,
            sourceType: 'module',
        });

        // Find main() function
        const mainFunction = findMainFunction(ast);
        t.truthy(mainFunction, 'should have main() function');

        if (!mainFunction) return;

        const body = mainFunction.body.body;
        t.true(body.length >= 2, 'main() should have at least 2 statements');

        if (body.length < 2) return;

        // Check first statement: logger.info(INFO.STARTING)
        const firstStmt = body[0];
        t.true(
            isLoggerCall(firstStmt, 'info', 'INFO', 'STARTING'),
            'first statement should be logger.info(INFO.STARTING)'
        );

        // Check last statement: logger.info(INFO.STARTED)
        const lastStmt = body[body.length - 1];
        t.true(
            isLoggerCall(lastStmt, 'info', 'INFO', 'STARTED'),
            'last statement should be logger.info(INFO.STARTED)'
        );
    });
}
