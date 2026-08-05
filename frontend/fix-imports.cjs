const fs = require("fs");
const path = require("path");

const SRC_DIR = path.resolve(__dirname, "src");

function getRelativePath(fromFile, toPath) {
  // toPath is like "components/auth/AuthShell" (without leading src/)
  const fromDir = path.dirname(fromFile);
  const toAbsolute = path.join(SRC_DIR, toPath);
  let rel = path.relative(fromDir, toAbsolute).replace(/\\/g, "/");
  if (!rel.startsWith(".")) rel = "./" + rel;
  return rel;
}

function getAllFiles(dir, exts = [".tsx", ".ts"]) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...getAllFiles(full, exts));
    } else if (exts.includes(path.extname(entry.name))) {
      results.push(full);
    }
  }
  return results;
}

const files = getAllFiles(SRC_DIR);
let totalFixed = 0;

for (const file of files) {
  let content = fs.readFileSync(file, "utf-8");
  let modified = false;

  // Match all @/ import/export paths
  const newContent = content.replace(
    /from\s+"@\/([^"]+)"/g,
    (match, importPath) => {
      const rel = getRelativePath(file, importPath);
      modified = true;
      return `from "${rel}"`;
    }
  );

  if (modified && newContent !== content) {
    fs.writeFileSync(file, newContent, "utf-8");
    const count = (content.match(/from\s+"@\//g) || []).length;
    console.log(`Fixed ${count} import(s) in: ${path.relative(SRC_DIR, file)}`);
    totalFixed++;
  }
}

console.log(`\nDone! Fixed ${totalFixed} file(s).`);
