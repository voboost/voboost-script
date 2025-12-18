import * as acorn from 'acorn';

/**
 * Remove export statements from minified code using AST parsing
 * @param {string} code - Minified source code
 * @returns {string} Code without exports
 */
export function stripExports(code) {
    try {
        // Parse the code into AST
        const ast = acorn.parse(code, {
            ecmaVersion: 2020,
            sourceType: 'script'
        });

        // Find the IIFE body
        if (ast.body.length === 0) return code;

        const topExpr = ast.body[0];
        if (topExpr.type !== 'ExpressionStatement') return code;

        let iifeBody = null;

        // Handle !function(){}() pattern
        if (topExpr.expression.type === 'UnaryExpression' &&
            topExpr.expression.operator === '!' &&
            topExpr.expression.argument.type === 'CallExpression' &&
            topExpr.expression.argument.callee.type === 'FunctionExpression') {
            iifeBody = topExpr.expression.argument.callee.body;
        }

        if (!iifeBody || !iifeBody.body) return code;

        // Find export statements (e.name = value)
        const exportStatements = [];
        for (const stmt of iifeBody.body) {
            if (stmt.type === 'ExpressionStatement' &&
                stmt.expression.type === 'AssignmentExpression' &&
                stmt.expression.left.type === 'MemberExpression' &&
                stmt.expression.left.object.type === 'Identifier' &&
                stmt.expression.left.object.name === 'e') {
                exportStatements.push(stmt);
            }
        }

        if (exportStatements.length === 0) return code;

        // Remove export statements by position (from end to start)
        exportStatements.sort((a, b) => b.start - a.start);

        let result = code;
        for (const stmt of exportStatements) {
            const before = result.substring(0, stmt.start);
            const after = result.substring(stmt.end);

            // Remove trailing comma or semicolon after the statement
            const afterCleaned = after.replace(/^[,;]\s*/, '');

            result = before + afterCleaned;
        }

        return result;

    } catch (error) {
        // If parsing fails, return original code
        console.warn('Failed to parse code for export stripping:', error.message);
        return code;
    }
}
