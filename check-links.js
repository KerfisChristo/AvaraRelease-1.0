const fs = require('fs');

const actualFiles = fs.readdirSync('.').filter(f => f.endsWith('.html'));
const byLower = {};
for (const f of actualFiles) byLower[f.toLowerCase()] = f;

const scanFiles = fs.readdirSync('.').filter(f => f.endsWith('.html') || f === 'server.js' || f === 'app.js');
const problems = [];

for (const f of scanFiles) {
  const text = fs.readFileSync(f, 'utf8');
  const re = /[\/'"`]([A-Za-z0-9_-]+\.html)\b/g;
  let m;
  const seen = new Set();
  while ((m = re.exec(text))) {
    const ref = m[1];
    if (seen.has(ref)) continue;
    seen.add(ref);
    if (byLower[ref.toLowerCase()]) {
      if (byLower[ref.toLowerCase()] !== ref) {
        problems.push(`${f}: "${ref}" should be "${byLower[ref.toLowerCase()]}"`);
      }
    } else {
      problems.push(`${f}: references missing page "${ref}"`);
    }
  }
}
console.log(problems.length ? [...new Set(problems)].join('\n') : 'No mismatches');
console.log('Total: ' + new Set(problems).size);
