// Flat config for ESLint v9+ (works with Node 20+ native --test).
// Zero-dependency linting: only the built-in `eslint` npm package is needed
// (installed as a devDependency).
export default [
  {
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
      globals: {
        // Node.js globals
        process: 'readonly',
        console: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        fetch: 'readonly',
        URL: 'readonly',
        Buffer: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
      },
    },
    rules: {
      // ── Error prevention ──────────────────────────────────────────────
      'no-undef': 'error',
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-unreachable': 'error',
      'no-fallthrough': 'error',
      'no-console': 'off', // server uses console for startup logging
      'no-process-exit': 'off', // CLI tools exit explicitly
      'no-empty': ['error', { allowEmptyCatch: true }],

      // ── Style consistency ─────────────────────────────────────────────
      'prefer-const': 'warn',
      'no-var': 'error',
      'eqeqeq': ['error', 'always'],
      'semi': ['error', 'always'],
      'quotes': ['error', 'single', { avoidEscape: true, allowTemplateLiterals: true }],

      // ── Security ───────────────────────────────────────────────────────
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
    },
  },
  {
    // Test files: relax some rules
    files: ['test/**/*.js'],
    languageOptions: {
      globals: {
        // node:test provides `test`, `describe`, `it`, `before`, `after`, etc.
        test: 'readonly',
        describe: 'readonly',
        it: 'readonly',
        before: 'readonly',
        after: 'readonly',
        beforeEach: 'readonly',
        afterEach: 'readonly',
      },
    },
    rules: {
      'no-console': 'off',
    },
  },
  {
    // Bin scripts
    files: ['bin/**/*.js'],
    rules: {
      'no-console': 'off',
      'no-process-exit': 'off',
    },
  },
  {
    ignores: ['node_modules/**', 'data/**'],
  },
];