const fs = require('fs');
const path = '/usr/src/app/dist/src/reports/latex-report.service.js';
let code = fs.readFileSync(path, 'utf8');

// Just add a file write after template render
code = code.replace(
  'const renderedTex = this.template(templateData);',
  [
    'const renderedTex = this.template(templateData);',
    '        try { fs.writeFileSync("/tmp/debug-tex.tex", renderedTex); } catch(ex) { console.log("TEX_WRITE_ERR", ex.message); }'
  ].join('\n')
);

fs.writeFileSync(path, code);
console.log('Patched');
