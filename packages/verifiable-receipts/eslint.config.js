// ESLint flat config: the recommended JS rules everywhere, and the
// recommended type-checked TypeScript rules for src/.
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/", "node_modules/"] },
  js.configs.recommended,
  {
    files: ["**/*.mjs", "**/*.js"],
    languageOptions: {
      globals: {
        process: "readonly",
        console: "readonly",
        Buffer: "readonly",
        URL: "readonly",
        AbortSignal: "readonly",
        fetch: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
      },
    },
  },
  {
    files: ["src/**/*.ts"],
    extends: [tseslint.configs.recommendedTypeChecked],
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
      // Rules implement an async interface; some have nothing to await.
      "@typescript-eslint/require-await": "off",
    },
  },
  {
    files: ["tests/**/*.ts", "conformance/**/*.ts", "conformance/**/*.d.mts"],
    extends: [tseslint.configs.recommended],
  },
);
