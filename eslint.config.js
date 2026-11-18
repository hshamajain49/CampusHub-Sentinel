import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';

// Values never reach SQL text. A template literal passed to query() may only interpolate SQL *fragments*:
// UPPER_CASE constants, Where-builder placeholders ($n) and whitelisted column maps, or literal-only choices.
// Anything else (e.g. `${email}`, `${req.body.x}`) is reported. (Same rule as CampusHub.)
const FRAGMENT = /^([A-Z][A-Z0-9_]*|where|limit|offset|order|filter|base|sets|params|w|nowP)$/;
function isFragment(n) {
  switch (n.type) {
    case 'Literal':
      return true;
    case 'Identifier':
      return FRAGMENT.test(n.name);
    case 'MemberExpression':
      return isFragment(n.object);
    case 'CallExpression':
      return isFragment(n.callee) && n.arguments.every(isFragment);
    case 'LogicalExpression':
      return isFragment(n.left) && isFragment(n.right);
    case 'ConditionalExpression':
      return isFragment(n.consequent) && isFragment(n.alternate);
    default:
      return false;
  }
}
const sqlNoValues = {
  meta: { type: 'problem', messages: { value: 'Use positional parameters ($1) instead of interpolating values into SQL.' } },
  create(context) {
    return {
      "CallExpression[callee.property.name='query'] > TemplateLiteral"(node) {
        for (const e of node.expressions) if (!isFragment(e)) context.report({ node: e, messageId: 'value' });
      },
    };
  },
};

export default tseslint.config(
  { ignores: ['**/dist/**', '**/node_modules/**', '.localdb/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: { globals: { ...globals.node } },
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },
  {
    files: ['backend/src/**/*.ts'],
    plugins: { sentinel: { rules: { 'sql-no-values': sqlNoValues } } },
    rules: { 'sentinel/sql-no-values': 'error' },
  },
  {
    files: ['frontend/src/**/*.{ts,tsx}'],
    languageOptions: { globals: { ...globals.browser } },
    plugins: { 'react-hooks': reactHooks },
    rules: { 'react-hooks/rules-of-hooks': 'error', 'react-hooks/exhaustive-deps': 'warn' },
  },
);
