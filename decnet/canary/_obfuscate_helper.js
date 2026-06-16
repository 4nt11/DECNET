// SPDX-License-Identifier: AGPL-3.0-or-later
// Node helper invoked by decnet.canary.obfuscator.
// Reads {code, options} JSON from stdin, writes obfuscated JS to stdout.
// Kept dependency-light on purpose: only javascript-obfuscator.
const JsObf = require('javascript-obfuscator');

let raw = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { raw += chunk; });
process.stdin.on('end', () => {
  try {
    const { code, options } = JSON.parse(raw);
    const result = JsObf.obfuscate(code, options || {});
    process.stdout.write(result.getObfuscatedCode());
  } catch (e) {
    process.stderr.write(String(e && e.stack || e));
    process.exit(2);
  }
});
