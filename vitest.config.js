import { defineConfig } from "vitest/config";

// Unit tests only — the Playwright specs under tests/e2e have their own runner.
export default defineConfig({
  test: {
    include: ["tests/unit/**/*.test.js"],
    environment: "node",
  },
});
