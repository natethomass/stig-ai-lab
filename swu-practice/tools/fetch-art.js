#!/usr/bin/env node
/* Fetch card images into img/ for your own local use.
 *
 * Nothing is committed: img/ is git-ignored apart from its README. This is a
 * personal cache for your copy of the app, pulled from a source YOU name.
 *
 * Two modes:
 *
 *   1. URL template - you know the pattern the source uses.
 *        node tools/fetch-art.js --template "https://host/cards/{slug}.png"
 *      Placeholders: {id} {name} {slug} {set} {number}
 *
 *   2. JSON index - you downloaded the source's card index and want the image
 *      URLs pulled out of it by card name.
 *        node tools/fetch-art.js --index cards.json
 *        node tools/fetch-art.js --index cards.json --url-field art.front
 *      The index may be an array or any nested object; entries are matched on a
 *      name field, and the image URL is auto-detected unless you name the field.
 *
 * Useful flags:
 *   --out <dir>      where to write (default img)
 *   --only <ids>     comma-separated card ids
 *   --include-opponent  also fetch the generic sparring deck (it has no real art)
 *   --delay <ms>     pause between requests (default 300 - be polite to the host)
 *   --overwrite      re-download files that already exist
 *   --dry-run        print what would happen, fetch nothing
 *
 * Check the source's terms of use before pointing this at it, and keep the
 * delay sane. This is a per-card fetch for one deck, not a site scraper.
 */
'use strict';

var fs = require('fs');
var path = require('path');
var https = require('https');
var http = require('http');

var ROOT = path.join(__dirname, '..');
['js/art.js', 'js/cards.js', 'js/opponent-deck.js'].forEach(function (f) {
  require(path.join(ROOT, f));
});

// ------------------------------------------------------------------- args
function parseArgs(argv) {
  var out = { delay: 300, outDir: 'img' };
  for (var i = 2; i < argv.length; i++) {
    var a = argv[i];
    var next = function () { return argv[++i]; };
    if (a === '--template') out.template = next();
    else if (a === '--index') out.index = next();
    else if (a === '--url-field') out.urlField = next();
    else if (a === '--name-field') out.nameField = next();
    else if (a === '--out') out.outDir = next();
    else if (a === '--only') out.only = next().split(',').map(function (s) { return s.trim(); });
    else if (a === '--delay') out.delay = Number(next());
    else if (a === '--include-opponent') out.includeOpponent = true;
    else if (a === '--overwrite') out.overwrite = true;
    else if (a === '--dry-run') out.dryRun = true;
    else if (a === '--help' || a === '-h') out.help = true;
    else { console.error('Unknown argument: ' + a); out.help = true; }
  }
  return out;
}

function usage() {
  var header = fs.readFileSync(__filename, 'utf8').split('*/')[0];
  console.log(header.replace(/^#!.*\n/, '').replace(/^\/\* ?/, '').replace(/^ \* ?/gm, ''));
}

// ------------------------------------------------------------------ cards
function cardList(opts) {
  var sets = [globalThis.SWU_CARDS];
  if (opts.includeOpponent) sets.push(globalThis.SWU_OPPONENT);
  var seen = {}, out = [];
  sets.forEach(function (set) {
    [set.LEADER, set.BASE].concat(set.DECK).forEach(function (def) {
      if (!def || seen[def.id]) return;
      seen[def.id] = true;
      out.push(def);
    });
  });
  if (opts.only) out = out.filter(function (d) { return opts.only.indexOf(d.id) >= 0; });
  return out;
}

function normalize(name) {
  return String(name || '').toLowerCase().replace(/['’]/g, '').replace(/[^a-z0-9]+/g, ' ').trim();
}

// --------------------------------------------------------------- JSON index
// The index shape differs between sources, so walk it and collect every object
// that carries something name-like.
function collectEntries(node, acc) {
  if (!node || typeof node !== 'object') return acc;
  if (Array.isArray(node)) { node.forEach(function (n) { collectEntries(n, acc); }); return acc; }
  var nameKeys = ['name', 'title', 'cardName', 'Name', 'Title'];
  for (var i = 0; i < nameKeys.length; i++) {
    if (typeof node[nameKeys[i]] === 'string') { acc.push(node); break; }
  }
  Object.keys(node).forEach(function (k) { collectEntries(node[k], acc); });
  return acc;
}

function readPath(obj, dotted) {
  return dotted.split('.').reduce(function (o, k) {
    return (o == null) ? undefined : o[k];
  }, obj);
}

function looksLikeImage(v) {
  return typeof v === 'string' && /^https?:\/\//.test(v) && /\.(png|jpe?g|webp|avif)(\?|$)/i.test(v);
}

function findImageUrl(entry, urlField) {
  if (urlField) {
    var explicit = readPath(entry, urlField);
    return typeof explicit === 'string' ? explicit : null;
  }
  var found = null;
  (function walk(node, depth) {
    if (found || !node || typeof node !== 'object' || depth > 4) return;
    Object.keys(node).forEach(function (k) {
      if (found) return;
      var v = node[k];
      if (looksLikeImage(v)) { found = v; return; }
      if (v && typeof v === 'object') walk(v, depth + 1);
    });
  })(entry, 0);
  return found;
}

function entryName(entry, nameField) {
  if (nameField) return readPath(entry, nameField);
  return entry.name || entry.title || entry.cardName || entry.Name || entry.Title;
}

function buildIndexMap(file, opts) {
  var raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  var entries = collectEntries(raw, []);
  var map = {};
  entries.forEach(function (e) {
    var n = normalize(entryName(e, opts.nameField));
    if (!n || map[n]) return;
    var url = findImageUrl(e, opts.urlField);
    if (url) map[n] = url;
  });
  return map;
}

// ---------------------------------------------------------------- download
function urlFromTemplate(template, def) {
  var set = (def.set || '').split(/\s+/)[0] || '';
  var number = (def.set || '').split(/\s+/)[1] || '';
  return template
    .replace(/\{id\}/g, def.id)
    .replace(/\{name\}/g, encodeURIComponent(def.name))
    .replace(/\{slug\}/g, normalize(def.name).replace(/ /g, '-'))
    .replace(/\{set\}/g, set)
    .replace(/\{number\}/g, number);
}

function download(url, dest, redirects) {
  return new Promise(function (resolve, reject) {
    if ((redirects || 0) > 5) return reject(new Error('too many redirects'));
    var mod = url.indexOf('https:') === 0 ? https : http;
    var req = mod.get(url, { headers: { 'User-Agent': 'swu-practice-art-fetch' } }, function (res) {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        var next = new URL(res.headers.location, url).toString();
        return resolve(download(next, dest, (redirects || 0) + 1));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error('HTTP ' + res.statusCode));
      }
      var type = res.headers['content-type'] || '';
      if (type && type.indexOf('image/') !== 0) {
        res.resume();
        return reject(new Error('not an image (' + type + ')'));
      }
      var chunks = [];
      res.on('data', function (c) { chunks.push(c); });
      res.on('end', function () {
        var buf = Buffer.concat(chunks);
        if (!buf.length) return reject(new Error('empty response'));
        fs.writeFileSync(dest, buf);
        resolve(buf.length);
      });
    });
    req.on('error', reject);
    req.setTimeout(20000, function () { req.destroy(new Error('timeout')); });
  });
}

function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

// -------------------------------------------------------------------- main
(async function main() {
  var opts = parseArgs(process.argv);
  if (opts.help || (!opts.template && !opts.index)) {
    usage();
    process.exit(opts.help ? 0 : 1);
  }

  var outDir = path.isAbsolute(opts.outDir) ? opts.outDir : path.join(ROOT, opts.outDir);
  if (!opts.dryRun) fs.mkdirSync(outDir, { recursive: true });

  var indexMap = opts.index ? buildIndexMap(opts.index, opts) : null;
  if (indexMap) console.log('Index: ' + Object.keys(indexMap).length + ' entries with an image URL.');

  var cards = cardList(opts);
  console.log('Cards to fetch: ' + cards.length + (opts.dryRun ? ' (dry run)' : ''));

  var saved = 0, skipped = 0, missing = [], failed = [];
  for (var i = 0; i < cards.length; i++) {
    var def = cards[i];
    var dest = path.join(outDir, def.id + '.png');
    if (!opts.overwrite && fs.existsSync(dest)) { skipped++; continue; }

    var url = indexMap ? indexMap[normalize(def.name)] : urlFromTemplate(opts.template, def);
    if (!url) { missing.push(def.name); continue; }

    if (opts.dryRun) { console.log('  would fetch ' + def.id + ' <- ' + url); saved++; continue; }
    try {
      var bytes = await download(url, dest);
      saved++;
      console.log('  ' + def.id + '  ' + (bytes / 1024).toFixed(0) + ' KB');
    } catch (e) {
      failed.push(def.name + ' (' + e.message + ')');
    }
    if (opts.delay) await sleep(opts.delay);
  }

  console.log('\nSaved ' + saved + ', already present ' + skipped +
    ', no URL ' + missing.length + ', failed ' + failed.length + '.');
  if (missing.length) console.log('No URL for: ' + missing.join(', '));
  if (failed.length) console.log('Failed: ' + failed.join(', '));
  if (saved && !opts.dryRun) console.log('\nNow open the app and choose Card art -> Local folder.');
})().catch(function (e) {
  console.error('Error: ' + e.message);
  process.exit(1);
});
