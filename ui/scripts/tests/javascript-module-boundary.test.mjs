import assert from "node:assert/strict";
import test from "node:test";
import { assertClosedJavaScriptModule } from "../javascript-module-boundary.mjs";

test("accepts a closed bundle, shadowed locals, and loader-shaped inert text", () => {
  assert.doesNotThrow(() =>
    assertClosedJavaScriptModule(
      [
        "const current = import.meta.url;",
        `const strings = ['import("string-only")', "require('string-only')"];`,
        'const template = `module.require("template-only")`;',
        "const pattern = /import\\([^)]+\\)|require\\([^)]+\\)/u;",
        'const metadata = { require: "property-name", import: "property-name" };',
        "const module = { require: () => 'local', exports: {} };",
        "const exports = module.exports;",
        "const __filename = 'local-file';",
        "const __dirname = 'local-directory';",
        "const invoke = (require) => require('local-only');",
        "function nested(module) { return module.require('local-only'); }",
        "function localBody() { require('local-only'); var require = () => 'local'; }",
        "class LocalStatic { static { var module = {}; module.local = true; } }",
        "switch (0) { case require('local-only'): let require; break; }",
        "{ const exports = {}; exports.local = true; }",
        "{ const globalThis = { module: {} }; globalThis.module.local = true; }",
        "{ const process = { getBuiltinModule: () => 'local' }; process.getBuiltinModule(); }",
        '// import("comment-only")',
        '/* module.require("comment-only") */',
        "export { current, strings, template, pattern, metadata, invoke, nested };",
      ].join("\n"),
      "test bundle",
    ),
  );
});

test("rejects every static module dependency", () => {
  for (const source of [
    'import value from "./dependency.js";',
    'import "./side-effect.js";',
    'export { value } from "./dependency.js";',
  ]) {
    assert.throws(
      () => assertClosedJavaScriptModule(source, "test bundle"),
      /found static import/u,
    );
  }
});

test("rejects literal, template, and computed dynamic imports", () => {
  for (const source of [
    'import("./dependency.js")',
    "import(`./${name}.js`)",
    "import(moduleName)",
  ]) {
    assert.throws(
      () => assertClosedJavaScriptModule(source, "test bundle"),
      /found dynamic import/u,
    );
  }
});

test("rejects ambient direct, indirect, template, and computed CommonJS require", () => {
  for (const source of [
    'require("dependency")',
    "require(`dependency`)",
    "require(`./${name}.js`)",
    "require(moduleName)",
    '(0, require)("dependency")',
    "const load = require; load(moduleName)",
    'function defaults(value = require("dependency")) { var require; }',
    'switch (require("dependency")) { case 0: let require; }',
  ]) {
    assert.throws(
      () => assertClosedJavaScriptModule(source, "test bundle"),
      /found ambient CommonJS require/u,
    );
  }
});

test("rejects direct, computed, and aliased ambient CommonJS references", () => {
  for (const source of [
    'module.require("dependency")',
    "module.require(moduleName)",
    'module["require"]("dependency")',
    "module[`require`](`./${name}.js`)",
    "const load = module.require; load(moduleName)",
    'const loader = module; loader.require("dependency")',
    'const { require: load } = module; load("dependency")',
    'module["req" + "uire"]("dependency")',
    "module[loader](moduleName)",
    "exports.value = 1",
    "console.log(__filename, __dirname)",
    "{ const module = {}; module.local = true; } module.require('dependency')",
    'class LocalStatic { static { var module; } } module.require("dependency")',
  ]) {
    assert.throws(
      () => assertClosedJavaScriptModule(source, "test bundle"),
      /found ambient CommonJS (?:module|exports|__filename|__dirname)/u,
    );
  }
});

test("rejects global and process loader escape hatches", () => {
  for (const source of [
    'globalThis.module.createRequire(import.meta.url)("node:path")',
    'globalThis["require"]("dependency")',
    'global[`module`].createRequire(import.meta.url)("node:path")',
    'process.getBuiltinModule("module")',
    "process[`mainModule`]",
    "globalThis.process.dlopen",
    "const { module: loader } = globalThis;",
    "({ require: loader } = global);",
    "const { getBuiltinModule } = process;",
    "const { process: { binding } } = globalThis;",
  ]) {
    assert.throws(
      () => assertClosedJavaScriptModule(source, "test bundle"),
      /found (?:global CommonJS|Node process\.)/u,
    );
  }
});

test("handles catch, loop, class, shorthand, and export scopes", () => {
  for (const source of [
    "try { throw {}; } catch ({ module = {} }) { module.local = true; }",
    "for (let require of [require]) { void require; }",
    "const Named = class module extends Object { static value = module; };",
    "const module = {}; const shorthand = { module }; export { shorthand as module };",
    "const module = 1; export { module as local };",
  ]) {
    assert.doesNotThrow(() =>
      assertClosedJavaScriptModule(source, "test bundle"),
    );
  }

  for (const source of [
    'try { throw {}; } catch ({ value = require("dependency") }) {}',
    'for (const item of [require("dependency")]) { void item; }',
    "const Derived = class extends module.Base {};",
    "export default module;",
    "const shorthand = { module };",
  ]) {
    assert.throws(
      () => assertClosedJavaScriptModule(source, "test bundle"),
      /found ambient CommonJS (?:module|require)/u,
    );
  }
});

test("rejects syntax that is invalid in an ECMAScript module", () => {
  for (const source of [
    "const value = ;",
    "with ({}) {}",
    "010;",
    "let duplicate; let duplicate;",
    "if (true) function annexB() {}",
  ]) {
    assert.throws(
      () => assertClosedJavaScriptModule(source, "test bundle"),
      /test bundle must be valid JavaScript/u,
    );
  }
});
