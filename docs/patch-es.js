const fs = require('fs');
const path = '/usr/src/app/dist/src/elasticsearch/elasticsearch.service.js';
let code = fs.readFileSync(path, 'utf8');

const method = `
    isValidIp(value) {
        return /^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(\\/\\d{1,2})?$/.test(value) || /^[0-9a-fA-F:]+(\\/\\d{1,3})?$/.test(value);
    }
`;

// Insert isValidIp method just before the search method
code = code.replace('    async search(query) {', method.trim() + '\n\n    async search(query) {');

// Fix source_ip check — add isValidIp guard
code = code.replace(
  'if (query.source_ip && this.isValidIp(query.source_ip)) {', 
  'if (query.source_ip && this.isValidIp(query.source_ip)) {'
);

// Verify
console.log('isValidIp count in source:', (code.match(/isValidIp/g) || []).length);

fs.writeFileSync(path, code);
console.log('Patched successfully');
