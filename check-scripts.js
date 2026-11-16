const fs = require('fs');
const vm = require('vm');
const files = fs.readdirSync('.').filter(f => f.endsWith('.html'));
let problems = 0;
for (const f of files) {
  const html = fs.readFileSync(f, 'utf8');
  const re = /<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/gi;
  let m, idx = 0;
  while ((m = re.exec(html))) {
    idx++;
    const code = m[1];
    try {
      new vm.Script(code);
    } catch (e) {
      problems++;
      const before = html.slice(0, m.index).split('\n').length;
      console.log('SYNTAX ERROR in ' + f + ' script#' + idx + ' (html line ~' + before + '): ' + e.message);
    }
  }
}
console.log('Done. Problems: ' + problems);
