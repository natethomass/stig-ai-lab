#!/usr/bin/env node
/* Build dist/artifact.html for hosting.
 *
 * The host supplies the document skeleton (doctype, <html>, <head> with charset
 * and viewport, <body>), so the hosted page is index.html with those wrappers
 * removed - keeping the <title>, the stylesheet link and the scripts, which are
 * published alongside it. index.html stays the single source of truth.
 */
'use strict';
var fs = require('fs');
var path = require('path');

var ROOT = path.join(__dirname, '..');
var html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');

function section(tag) {
  var m = html.match(new RegExp('<' + tag + '[^>]*>([\\s\\S]*?)<\\/' + tag + '>', 'i'));
  if (!m) throw new Error('index.html has no <' + tag + '> section');
  return m[1];
}

var head = section('head')
  .replace(/<meta charset[^>]*>\s*/i, '')
  .replace(/<meta name="viewport"[^>]*>\s*/i, '')
  .replace(/<link rel="icon"[^>]*>\s*/i, '')       // the host takes an emoji instead
  .trim();
var body = section('body').trim();

var out = head + '\n\n' + body + '\n';
var dest = path.join(ROOT, 'dist');
fs.mkdirSync(dest, { recursive: true });
fs.writeFileSync(path.join(dest, 'artifact.html'), out);

['<title>', 'styles.css', 'js/ui.js'].forEach(function (needle) {
  if (out.indexOf(needle) < 0) throw new Error('built page is missing ' + needle);
});
if (/<(!doctype|html|head|body)\b/i.test(out)) throw new Error('wrapper tags survived the strip');

console.log('dist/artifact.html  ' + (out.length / 1024).toFixed(1) + ' KB');
