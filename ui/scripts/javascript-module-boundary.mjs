import { spawnSync } from "node:child_process";
import { parseAst } from "vite";

/**
 * Vite's renderer and hydration entry are embedded as single immutable files.
 * Static module edges, ambient CommonJS access, and known Node loader escape
 * hatches would leave that serving boundary at runtime.
 */
export function assertClosedJavaScriptModule(source, label) {
  assertValidModuleSyntax(source, label);

  let ast;
  try {
    ast = parseAst(source, { sourceType: "module" });
  } catch (error) {
    throw new Error(`${label} must be valid JavaScript`, { cause: error });
  }

  const { bindings, scopes } = indexLexicalBindings(ast);
  const references = [];
  const pending = [{ node: ast, parent: null, property: null }];
  while (pending.length > 0) {
    const current = pending.pop();
    const reference = describeModuleReference(
      current.node,
      current.parent,
      current.property,
      scopes.get(current.node),
      bindings,
    );
    if (reference !== null) {
      references.push(reference);
    }

    for (const [property, value] of Object.entries(current.node)) {
      if (Array.isArray(value)) {
        for (const child of value) {
          if (isAstNode(child)) {
            pending.push({ node: child, parent: current.node, property });
          }
        }
      } else if (isAstNode(value)) {
        pending.push({ node: value, parent: current.node, property });
      }
    }
  }

  if (references.length === 0) {
    return;
  }

  references.sort((left, right) => left.offset - right.offset);
  const first = references[0];
  throw new Error(
    `${label} must be self-contained; found ${first.description} at source offset ${first.offset}`,
  );
}

function describeModuleReference(node, parent, property, scope, bindings) {
  if (node.type === "ImportDeclaration") {
    return reference(node, "static import", node.source);
  }
  if (
    (node.type === "ExportAllDeclaration" || node.type === "ExportNamedDeclaration") &&
    node.source !== null
  ) {
    return reference(node, "static import", node.source);
  }
  if (node.type === "ImportExpression") {
    return reference(node, "dynamic import", node.source);
  }
  const escapingLoader = describeEscapingLoaderReference(node, scope, bindings);
  if (escapingLoader !== null) {
    return escapingLoader;
  }
  if (
    node.type === "Identifier" &&
    COMMONJS_AMBIENT_IDENTIFIERS.has(node.name) &&
    !bindings.has(node) &&
    isIdentifierReference(parent, property) &&
    !isLexicallyBound(scope, node.name)
  ) {
    return reference(
      node,
      `ambient CommonJS ${node.name}`,
      callArgument(parent, property),
    );
  }
  return null;
}

function assertValidModuleSyntax(source, label) {
  const result = spawnSync(
    process.execPath,
    ["--check", "--input-type=module"],
    {
      encoding: "utf8",
      input: source,
      maxBuffer: 1024 * 1024,
      timeout: 10_000,
    },
  );
  if (result.error !== undefined) {
    throw new Error(`${label} JavaScript module syntax check failed`, {
      cause: result.error,
    });
  }
  if (result.status !== 0) {
    throw new Error(`${label} must be valid JavaScript module syntax`);
  }
}

function describeEscapingLoaderReference(node, scope, bindings) {
  if (node.type === "MemberExpression") {
    const path = staticMemberPath(node, scope, bindings);
    const description = restrictedLoaderDescription(path);
    if (description !== null) {
      return reference(node, description, null);
    }
  }

  const destructuring = destructuringAccess(node);
  if (destructuring === null) {
    return null;
  }
  const base = staticMemberPath(destructuring.source, scope, bindings);
  if (base === null) {
    return null;
  }
  for (const suffix of objectPatternPaths(destructuring.pattern)) {
    const description = restrictedLoaderDescription([...base, ...suffix]);
    if (description !== null) {
      return reference(node, description, null);
    }
  }
  return null;
}

function staticMemberPath(node, scope, bindings) {
  if (node.type === "ChainExpression") {
    return staticMemberPath(node.expression, scope, bindings);
  }
  if (node.type === "Identifier") {
    if (
      GLOBAL_LOADER_ROOTS.has(node.name) &&
      !bindings.has(node) &&
      !isLexicallyBound(scope, node.name)
    ) {
      return [node.name];
    }
    return null;
  }
  if (node.type !== "MemberExpression") {
    return null;
  }
  const base = staticMemberPath(node.object, scope, bindings);
  const propertyName = staticPropertyName(node);
  return base === null || propertyName === null
    ? null
    : [...base, propertyName];
}

function staticPropertyName(member) {
  if (!member.computed && member.property.type === "Identifier") {
    return member.property.name;
  }
  return member.computed ? staticString(member.property) : null;
}

const GLOBAL_LOADER_ROOTS = new Set(["global", "globalThis", "process"]);
const PROCESS_LOADER_PROPERTIES = new Set([
  "_linkedBinding",
  "binding",
  "dlopen",
  "getBuiltinModule",
  "mainModule",
]);

function restrictedLoaderDescription(path) {
  if (path === null) {
    return null;
  }
  const [root, first, second] = path;
  if (
    (root === "global" || root === "globalThis") &&
    (first === "module" || first === "require")
  ) {
    return `global CommonJS ${first} access`;
  }
  if (root === "process" && PROCESS_LOADER_PROPERTIES.has(first)) {
    return `Node process.${first} loader access`;
  }
  if (
    (root === "global" || root === "globalThis") &&
    first === "process" &&
    PROCESS_LOADER_PROPERTIES.has(second)
  ) {
    return `Node process.${second} loader access`;
  }
  return null;
}

function destructuringAccess(node) {
  if (
    node.type === "VariableDeclarator" &&
    node.id.type === "ObjectPattern" &&
    node.init !== null
  ) {
    return { pattern: node.id, source: node.init };
  }
  if (
    node.type === "AssignmentExpression" &&
    node.left.type === "ObjectPattern"
  ) {
    return { pattern: node.left, source: node.right };
  }
  return null;
}

function objectPatternPaths(pattern) {
  const paths = [];
  for (const property of pattern.properties) {
    if (property.type === "RestElement") {
      continue;
    }
    const name = property.computed
      ? staticString(property.key)
      : property.key.type === "Identifier"
        ? property.key.name
        : staticString(property.key);
    if (name === null) {
      continue;
    }
    const value = property.value.type === "AssignmentPattern"
      ? property.value.left
      : property.value;
    if (value.type === "ObjectPattern") {
      for (const nested of objectPatternPaths(value)) {
        paths.push([name, ...nested]);
      }
    } else {
      paths.push([name]);
    }
  }
  return paths;
}

const COMMONJS_AMBIENT_IDENTIFIERS = new Set([
  "require",
  "module",
  "exports",
  "__filename",
  "__dirname",
]);

function reference(node, description, source) {
  const specifier = staticString(source);
  const target = source === null
    ? ""
    : specifier === null
      ? " with a computed specifier"
      : ` of ${JSON.stringify(specifier)}`;
  return { description: `${description}${target}`, offset: node.start };
}

function callArgument(parent, property) {
  return parent?.type === "CallExpression" && property === "callee"
    ? parent.arguments[0] ?? null
    : null;
}

function staticString(node) {
  if (node?.type === "Literal" && typeof node.value === "string") {
    return node.value;
  }
  if (node?.type === "TemplateLiteral" && node.expressions.length === 0) {
    return node.quasis[0]?.value.cooked ?? node.quasis[0]?.value.raw ?? "";
  }
  return null;
}

function isIdentifierReference(parent, property) {
  if (parent === null) {
    return true;
  }
  if (
    parent.computed !== true &&
    ((parent.type === "MemberExpression" && property === "property") ||
      ((parent.type === "Property" || parent.type === "MethodDefinition") &&
        property === "key") ||
      (parent.type === "PropertyDefinition" && property === "key") ||
      (parent.type === "ExportSpecifier" && property === "exported") ||
      parent.type === "MetaProperty")
  ) {
    return false;
  }
  return !(
    property === "label" &&
    (parent.type === "LabeledStatement" ||
      parent.type === "BreakStatement" ||
      parent.type === "ContinueStatement")
  );
}

function indexLexicalBindings(ast) {
  const bindings = new WeakSet();
  const scopes = new WeakMap();
  const root = makeScope(null, true);

  function visit(node, currentScope) {
    if (node.type === "FunctionDeclaration" && node.id !== null) {
      bindPattern(node.id, currentScope, bindings);
    } else if (node.type === "ClassDeclaration" && node.id !== null) {
      bindPattern(node.id, currentScope, bindings);
    }

    if (isFunctionNode(node)) {
      visitFunction(node, currentScope);
      return;
    }

    if (node.type === "SwitchStatement") {
      scopes.set(node, currentScope);
      visit(node.discriminant, currentScope);
      const caseScope = makeScope(currentScope, false);
      for (const switchCase of node.cases) {
        visit(switchCase, caseScope);
      }
      return;
    }

    let scope = currentScope;
    if (node.type === "ClassDeclaration" || node.type === "ClassExpression") {
      scope = makeScope(currentScope, false);
      if (node.type === "ClassExpression" && node.id !== null) {
        bindPattern(node.id, scope, bindings);
      }
    } else if (introducesBlockScope(node)) {
      scope = makeScope(currentScope, node.type === "StaticBlock");
      if (node.type === "CatchClause" && node.param !== null) {
        bindPattern(node.param, scope, bindings);
      }
    }

    visitInScope(node, scope);
  }

  function visitFunction(node, currentScope) {
    const parameterScope = makeScope(currentScope, false);
    if (node.type === "FunctionExpression" && node.id !== null) {
      bindPattern(node.id, parameterScope, bindings);
    }
    for (const parameter of node.params) {
      bindPattern(parameter, parameterScope, bindings);
    }

    scopes.set(node, parameterScope);
    if (node.id !== null) {
      visit(node.id, parameterScope);
    }
    for (const parameter of node.params) {
      visit(parameter, parameterScope);
    }

    if (node.body.type === "BlockStatement") {
      const bodyScope = makeScope(parameterScope, true);
      visitInScope(node.body, bodyScope);
    } else {
      visit(node.body, parameterScope);
    }
  }

  function visitInScope(node, scope) {
    scopes.set(node, scope);

    if (node.type === "VariableDeclaration") {
      const declarationScope = node.kind === "var"
        ? nearestVarScope(scope)
        : scope;
      for (const declaration of node.declarations) {
        bindPattern(declaration.id, declarationScope, bindings);
      }
    } else if (node.type === "ImportDeclaration") {
      for (const specifier of node.specifiers) {
        bindPattern(specifier.local, scope, bindings);
      }
    }

    for (const value of Object.values(node)) {
      if (Array.isArray(value)) {
        for (const child of value) {
          if (isAstNode(child)) {
            visit(child, scope);
          }
        }
      } else if (isAstNode(value)) {
        visit(value, scope);
      }
    }
  }

  visit(ast, root);
  return { bindings, scopes };
}

function makeScope(parent, isVarScope) {
  return { bindings: new Set(), isVarScope, parent };
}

function nearestVarScope(scope) {
  let current = scope;
  while (!current.isVarScope && current.parent !== null) {
    current = current.parent;
  }
  return current;
}

function bindPattern(pattern, scope, bindings) {
  if (pattern.type === "Identifier") {
    scope.bindings.add(pattern.name);
    bindings.add(pattern);
    return;
  }
  if (pattern.type === "RestElement") {
    bindPattern(pattern.argument, scope, bindings);
    return;
  }
  if (pattern.type === "AssignmentPattern") {
    bindPattern(pattern.left, scope, bindings);
    return;
  }
  if (pattern.type === "ArrayPattern") {
    for (const element of pattern.elements) {
      if (element !== null) {
        bindPattern(element, scope, bindings);
      }
    }
    return;
  }
  if (pattern.type === "ObjectPattern") {
    for (const property of pattern.properties) {
      bindPattern(
        property.type === "RestElement" ? property.argument : property.value,
        scope,
        bindings,
      );
    }
  }
}

function isLexicallyBound(scope, name) {
  let current = scope;
  while (current !== undefined && current !== null) {
    if (current.bindings.has(name)) {
      return true;
    }
    current = current.parent;
  }
  return false;
}

function isFunctionNode(node) {
  return node.type === "FunctionDeclaration" ||
    node.type === "FunctionExpression" ||
    node.type === "ArrowFunctionExpression";
}

function introducesBlockScope(node) {
  return node.type === "BlockStatement" ||
    node.type === "CatchClause" ||
    node.type === "ForStatement" ||
    node.type === "ForInStatement" ||
    node.type === "ForOfStatement" ||
    node.type === "StaticBlock";
}

function isAstNode(value) {
  return value !== null && typeof value === "object" && typeof value.type === "string";
}
