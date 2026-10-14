import parentConfigs from '../../eslint.config.js'

export default [
  ...parentConfigs,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    files: ['tests/**/*.test.ts', 'tests/setup.ts', 'tests/helpers/**/*.ts'],
    rules: {
      // CLAUDE.md: "as Type assertions allowed in test files for test fixtures"
      '@typescript-eslint/consistent-type-assertions': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
      // Test cleanup patterns (e.g. delete process.env[key])
      '@typescript-eslint/no-dynamic-delete': 'off',
      // Untyped fixtures and mocks are acceptable in tests
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      // test helper functions don't need explicit return types
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/explicit-module-boundary-types': 'off',
      // unbound method references in mock/spy patterns
      '@typescript-eslint/unbound-method': 'off',
      // test assertion patterns like await expect(fn()).resolves.toBeUndefined()
      '@typescript-eslint/await-thenable': 'off',
      '@typescript-eslint/no-confusing-void-expression': 'off',
      // HTTP header names in object literals (content-type, anthropic-version)
      '@typescript-eslint/naming-convention': 'off',
      // test helpers returning fetch() are implicitly async-returning
      '@typescript-eslint/promise-function-async': 'off',
    },
  },
]
