#!/usr/bin/env node
const fs = require('fs/promises');
const path = require('path');
let ts;
try {
  ts = require('typescript');
} catch (err) {
  ts = null;
}

const projectDir = path.resolve(process.argv[2] || process.cwd());
const SKIP_DIRS = new Set(['.git', '.hg', '.svn', 'node_modules', 'dist', 'build', '.next', '.nuxt', '.turbo', '.expo']);
const EXTENSIONS = new Set(['.ts', '.tsx']);

async function collectFiles(target) {
  let stats;
  try {
    stats = await fs.stat(target);
  } catch (err) {
    console.warn(`[ubs-type-narrowing] Unable to access ${target}: ${err.message}`);
    return [];
  }

  if (stats.isFile()) {
    return EXTENSIONS.has(path.extname(target).toLowerCase()) ? [target] : [];
  }
  if (!stats.isDirectory()) {
    return [];
  }

  let entries;
  try {
    entries = await fs.readdir(target, { withFileTypes: true });
  } catch (err) {
    console.warn(`[ubs-type-narrowing] Skipping ${target}: ${err.message}`);
    return [];
  }

  let batches;
  try {
    batches = await Promise.all(entries.map(async (entry) => {
      if (entry.isSymbolicLink()) return [];
      if (SKIP_DIRS.has(entry.name)) return [];
      const fullPath = path.join(target, entry.name);
      if (entry.isDirectory()) {
        if (entry.name.startsWith('.') && entry.name.length > 1) return [];
        return collectFiles(fullPath);
      }
      if (entry.isFile() && EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
        return [fullPath];
      }
      return [];
    }));
  } catch (err) {
    console.warn(`[ubs-type-narrowing] Failed to enumerate ${target}: ${err.message}`);
    return [];
  }
  return batches.flat();
}

function formatLocation(file, sourceFile, pos) {
  const lc = sourceFile.getLineAndCharacterOfPosition(pos);
  return `${file}:${lc.line + 1}:${lc.character + 1}`;
}

async function analyzeFileWithTs(filePath) {
  const sourceText = await fs.readFile(filePath, 'utf8');
  const scriptKind = filePath.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const sourceFile = ts.createSourceFile(filePath, sourceText, ts.ScriptTarget.Latest, true, scriptKind);
  const results = [];
  const nextNavigationTerminators = new Set();
  const nextNavigationNamespaces = new Set();
  const nextNavigationNoReturnExports = new Set([
    'redirect',
    'permanentRedirect',
    'notFound',
    'forbidden',
    'unauthorized',
  ]);

  function collectNoReturnImports() {
    for (const stmt of sourceFile.statements) {
      if (!ts.isImportDeclaration(stmt)) continue;
      if (!ts.isStringLiteral(stmt.moduleSpecifier)) continue;
      if (stmt.moduleSpecifier.text !== 'next/navigation') continue;
      const clause = stmt.importClause;
      if (!clause || !clause.namedBindings) continue;
      const bindings = clause.namedBindings;
      if (ts.isNamedImports(bindings)) {
        for (const specifier of bindings.elements) {
          const imported = specifier.propertyName ? specifier.propertyName.text : specifier.name.text;
          if (nextNavigationNoReturnExports.has(imported)) {
            nextNavigationTerminators.add(specifier.name.text);
          }
        }
      } else if (ts.isNamespaceImport(bindings)) {
        nextNavigationNamespaces.add(bindings.name.text);
      }
    }
  }

  function extractGuardedIdentifier(expression) {
    if (ts.isBinaryExpression(expression)) {
      const op = expression.operatorToken.kind;
      if (
        op === ts.SyntaxKind.EqualsEqualsToken ||
        op === ts.SyntaxKind.EqualsEqualsEqualsToken
      ) {
        const left = ts.isIdentifier(expression.left) ? expression.left : null;
        const right = ts.isIdentifier(expression.right) ? expression.right : null;
        if (left && isNullish(expression.right)) return left;
        if (right && isNullish(expression.left)) return right;
        if (left && isUndefinedIdent(expression.right)) return left;
        if (right && isUndefinedIdent(expression.left)) return right;
      }
    }
    if (ts.isPrefixUnaryExpression(expression) && expression.operator === ts.SyntaxKind.ExclamationToken) {
      if (ts.isIdentifier(expression.operand)) {
        return expression.operand;
      }
      // Handle !x.prop (optional chain guard)
      if (ts.isPropertyAccessExpression(expression.operand) || ts.isElementAccessExpression(expression.operand)) {
        // For now, we only track simple identifiers, but we could expand this.
        // Returning null avoids false positives on complex expressions.
        return null;
      }
    }
    return null;
  }

  function isNullish(node) {
    return node.kind === ts.SyntaxKind.NullKeyword;
  }

  function isUndefinedIdent(node) {
    return ts.isIdentifier(node) && node.text === 'undefined';
  }

  function isKnownNoReturnCall(node) {
    if (!ts.isCallExpression(node)) return false;
    const callee = node.expression;
    if (ts.isIdentifier(callee)) {
      return nextNavigationTerminators.has(callee.text);
    }
    if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)) {
      return nextNavigationNamespaces.has(callee.expression.text) &&
        nextNavigationNoReturnExports.has(callee.name.text);
    }
    return false;
  }

  function blockHasExit(node) {
    if (ts.isReturnStatement(node) || ts.isThrowStatement(node)) return true;
    // `continue`/`break` end the current iteration or the enclosing
    // loop/switch, so the statements that follow in this block are only
    // reached when the guard did not fire (GH #76).
    if (ts.isContinueStatement(node) || ts.isBreakStatement(node)) return true;
    if (ts.isExpressionStatement(node) && isKnownNoReturnCall(node.expression)) return true;
    if (ts.isCallExpression(node) && isKnownNoReturnCall(node)) return true;
    if (ts.isBlock(node)) return node.statements.some(blockHasExit);
    if (ts.isIfStatement(node)) {
      return node.elseStatement ? blockHasExit(node.thenStatement) && blockHasExit(node.elseStatement) : false;
    }
    return false;
  }

  function statementRedefines(stmt, name) {
    if (ts.isVariableStatement(stmt)) {
      return stmt.declarationList.declarations.some((d) => ts.isIdentifier(d.name) && d.name.text === name);
    }
    if (ts.isExpressionStatement(stmt) && ts.isBinaryExpression(stmt.expression)) {
      if (stmt.expression.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(stmt.expression.left)) {
        return stmt.expression.left.text === name;
      }
    }
    return false;
  }

  function findUsageAfter(statements, startIndex, identifier) {
    const name = identifier.text;
    for (let i = startIndex + 1; i < statements.length; i++) {
      const stmt = statements[i];
      if (statementRedefines(stmt, name)) {
        return null;
      }
      let found = null;
      function search(node) {
        if (found) return;
        if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === name) {
          found = node.expression;
          return;
        }
        if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === name) {
          found = node.expression;
          return;
        }
        if (ts.isElementAccessExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === name) {
          found = node.expression;
          return;
        }
        ts.forEachChild(node, search);
      }
      search(stmt);
      if (found) return found;
    }
    return null;
  }

  function statementAssigns(stmt, name) {
    if (ts.isExpressionStatement(stmt) && ts.isBinaryExpression(stmt.expression)) {
      if (stmt.expression.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(stmt.expression.left)) {
        return stmt.expression.left.text === name;
      }
    }
    return false;
  }

  function blockAssigns(node, name) {
    if (statementAssigns(node, name)) return true;
    if (ts.isBlock(node)) {
      return node.statements.some((s) => blockAssigns(s, name));
    }
    if (ts.isIfStatement(node)) {
      return node.elseStatement ? blockAssigns(node.thenStatement, name) && blockAssigns(node.elseStatement, name) : false;
    }
    return false;
  }

  function visit(node) {
    if (ts.isBlock(node)) {
      const statements = node.statements;
      statements.forEach((stmt, idx) => {
        if (ts.isIfStatement(stmt)) {
          const guarded = extractGuardedIdentifier(stmt.expression);
          // If we have a guard, we expect the THEN block to EXIT if the guard was NEGATIVE (e.g. if (!x) return).
          // But extractGuardedIdentifier returns the identifier for both !x and x === null.
          // Wait, if the guard is `if (!x)`, then `x` is falsy in the THEN block.
          // So if the THEN block DOES NOT exit, then `x` remains falsy in the rest of the scope?
          // No, if `if (!x) return`, then `x` is truthy afterwards.
          // The logic below checks: if guarded && !else && !blockHasExit(then) -> warn if used.
          // This implies the guard was "if (x is bad) { log but don't exit }".
          // So if `if (!x) { log } x.foo()`, x might be null.
          // This logic seems correct for "guard clauses that fail to guard".
          
          if (guarded && !stmt.elseStatement && !blockHasExit(stmt.thenStatement)) {
            if (blockAssigns(stmt.thenStatement, guarded.text)) return;
            const usage = findUsageAfter(statements, idx, guarded);
            if (usage) {
              results.push({
                location: formatLocation(filePath, sourceFile, usage.getStart(sourceFile)),
                message: `Value '${guarded.text}' may still be null/undefined after guard`
              });
            }
          }
        }
      });
    }
    ts.forEachChild(node, visit);
  }

  collectNoReturnImports();
  visit(sourceFile);
  return results;
}

async function analyzeFileFallback(filePath) {
  const text = await fs.readFile(filePath, 'utf8');
  const lines = text.split(/\r?\n/);
  const results = [];
  const nextNavigationImport = /from\s+['"]next\/navigation['"]/.test(text) ||
    /require\(\s*['"]next\/navigation['"]\s*\)/.test(text);
  const noReturnCall = /\b(?:redirect|permanentRedirect|notFound|forbidden|unauthorized)\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Match both loose (==) and strict (===) equality to be consistent with AST analyzer
    const guard = line.match(/if\s*\(\s*!([A-Za-z_$][\w$]*)\b\s*\)/) || line.match(/if\s*\(\s*([A-Za-z_$][\w$]*)\b\s*===?\s*(?:null|undefined)\b\s*\)/);
    if (!guard) continue;
    const name = guard[1];
    // GH #76: `continue`/`break` terminate the iteration or the enclosing
    // loop/switch, so they guard the following statements exactly like
    // `return`/`throw` do.
    const terminator = /return\b|throw\b|continue\b|break\b/;
    let exits = false;
    // A single-line guard puts its terminator on the guard line itself
    // (`if (!value) continue;`), after the closing parenthesis.
    const guardTail = line.slice(guard.index + guard[0].length);
    if (terminator.test(guardTail) || (nextNavigationImport && noReturnCall.test(guardTail))) {
      exits = true;
    }
    for (let j = i + 1; !exits && j < Math.min(lines.length, i + 6); j++) {
      if (terminator.test(lines[j]) || (nextNavigationImport && noReturnCall.test(lines[j]))) {
        exits = true;
        break;
      }
    }
    if (exits) continue;
    
    // Regex to find usage: word boundary + name + (dot or bracket)
    // e.g. name.prop or name['prop']
    const usageRegex = new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:\\.|\\s*\\[)`);
    const assignmentRegex = new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*=`);

    for (let j = i + 1; j < Math.min(lines.length, i + 25); j++) {
      if (usageRegex.test(lines[j])) {
        results.push({
          location: `${filePath}:${j + 1}:1`,
          message: `Value '${name}' checked earlier but used without return (text heuristic)`
        });
        break;
      }
      if (assignmentRegex.test(lines[j])) break;
    }
  }
  return results;
}

async function main() {
  const files = await collectFiles(projectDir);
  if (files.length === 0) {
    return;
  }
  let total = 0;
  for (const file of files) {
    const issues = ts ? await analyzeFileWithTs(file) : await analyzeFileFallback(file);
    issues.forEach(({ location, message }) => {
      total++;
      console.log(`${location}\t${message}`);
    });
  }
  if (!ts) {
    console.log('[ubs-type-narrowing] TypeScript compiler not detected');
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
