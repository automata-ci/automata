import { describe, expect, it } from "vitest";
import {
  App,
  Shell,
  THEME_BOOTSTRAP_SCRIPT,
  ThemeToggle,
} from "../src/public";

describe("public package entrypoint", () => {
  it("exports the supported runtime surface", () => {
    expect(App).toBeTypeOf("function");
    expect(Shell).toBeTypeOf("function");
    expect(ThemeToggle).toBeTypeOf("function");
    expect(THEME_BOOTSTRAP_SCRIPT).toBeTypeOf("string");
  });
});
