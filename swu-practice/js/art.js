/* Optional card-art layer.
 *
 * No art ships with this app and none is downloaded into the repo: card images
 * are copyrighted, so you point this at a source you are entitled to use and it
 * loads in your browser only. Settings live in localStorage.
 *
 * Modes:
 *   off       text cards only (default)
 *   local     img/<card-id>.png next to index.html - drop in files you own
 *   template  a URL pattern, e.g. https://example.com/cards/{id}.png
 *
 * Placeholders in a template: {id} {name} {slug} {set} {number}
 * Anything that fails to load falls back to the text card silently.
 */
(function (global) {
  'use strict';

  var KEY = 'swu-practice-art';
  var config = { mode: 'off', template: '', numbers: {} };

  // One-tap template presets, so nobody has to type a URL on a phone.
  var PRESETS = [{
    id: 'swudb', name: 'SWUDB',
    template: 'https://swudb.com/cdn-cgi/image/quality=95/images/cards/{set}/{number}.png',
    needsNumbers: true
  }];
  var failed = {};                       // urls that 404'd, so we stop retrying

  function load() {
    try {
      var raw = global.localStorage && global.localStorage.getItem(KEY);
      if (raw) {
        var parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object') {
          config.mode = parsed.mode || 'off';
          config.template = parsed.template || '';
          config.numbers = (parsed.numbers && typeof parsed.numbers === 'object') ? parsed.numbers : {};
        }
      }
    } catch (e) { /* private mode, blocked storage - stay on defaults */ }
    return config;
  }

  function save(next) {
    config.mode = next.mode || 'off';
    config.template = next.template || '';
    if (next.numbers) config.numbers = next.numbers;
    failed = {};
    try {
      global.localStorage && global.localStorage.setItem(KEY, JSON.stringify(config));
    } catch (e) { /* not fatal - the setting just will not persist */ }
    return config;
  }

  function slug(name) {
    return String(name).toLowerCase().replace(/['’]/g, '').replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');
  }

  function urlFor(def) {
    if (!def || config.mode === 'off') return null;
    var url;
    if (config.mode === 'local') {
      url = 'img/' + def.id + '.png';
    } else if (config.mode === 'template' && config.template) {
      var parts = (def.set || '').split(/\s+/);
      var meta = config.numbers[def.id] || {};
      var set = def.setCode || meta.set || parts[0] || '';
      var number = def.number || meta.number || parts[1] || '';
      // A number-keyed template with no number would request a broken URL.
      if (/\{number\}/.test(config.template) && !number) return null;
      url = config.template
        .replace(/\{id\}/g, encodeURIComponent(def.id))
        .replace(/\{name\}/g, encodeURIComponent(def.name))
        .replace(/\{slug\}/g, slug(def.name))
        .replace(/\{set\}/g, encodeURIComponent(set))
        .replace(/\{number\}/g, encodeURIComponent(number));
    }
    if (!url || failed[url]) return null;
    return url;
  }

  function markFailed(url) { if (url) failed[url] = true; }

  // ---------------------------------------------------------- deck imports
  // Deck exports differ between sites and change over time, so rather than
  // targeting one schema this pulls (name, set, number) out of whatever it is
  // given - JSON of any shape, or a plain text list - and matches on name.
  function normName(n) {
    return String(n || '').toLowerCase().replace(/['’]/g, '')
      .replace(/[^a-z0-9]+/g, ' ').trim();
  }

  var NAME_KEYS = ['name', 'title', 'cardName', 'Name', 'Title'];
  var SET_KEYS = ['set', 'setCode', 'expansion', 'Set', 'setId'];
  var NUM_KEYS = ['number', 'cardNumber', 'collectorNumber', 'Number', 'num', 'no'];
  var ID_KEYS = ['id', 'cardId', 'code', 'Id'];

  function pick(obj, keys) {
    for (var i = 0; i < keys.length; i++) {
      var v = obj[keys[i]];
      if (typeof v === 'string' && v.trim()) return v.trim();
      if (typeof v === 'number') return String(v);
    }
    return null;
  }

  // "LAW_011", "LAW-11", "LAW011" -> { set: 'LAW', number: '011' }
  function splitCardCode(code) {
    var m = String(code).match(/^([A-Za-z]{2,4})[ _\-]?(\d{1,3})$/);
    return m ? { set: m[1].toUpperCase(), number: m[2] } : null;
  }

  function collectFromJson(node, out, depth) {
    if (!node || typeof node !== 'object' || (depth || 0) > 8) return out;
    if (Array.isArray(node)) {
      node.forEach(function (n) { collectFromJson(n, out, (depth || 0) + 1); });
      return out;
    }
    var name = pick(node, NAME_KEYS);
    var set = pick(node, SET_KEYS);
    var number = pick(node, NUM_KEYS);
    var code = pick(node, ID_KEYS);
    if (code && (!set || !number)) {
      var split = splitCardCode(code);
      if (split) { set = set || split.set; number = number || split.number; }
    }
    if (name && set && number) out.push({ name: name, set: set.toUpperCase(), number: number });
    Object.keys(node).forEach(function (k) {
      collectFromJson(node[k], out, (depth || 0) + 1);
    });
    return out;
  }

  function collectFromText(text) {
    var out = [];
    text.split(/\r?\n/).forEach(function (line) {
      if (!line.trim()) return;
      // "2x Storm Raider (LAW) 12" | "1 LAW_011 Darth Vader" | "Kage Elite | LAW 104"
      var codeMatch = line.match(/\(([A-Za-z]{2,4})\)\s*[-|#]?\s*(\d{1,3})\b/)
        || line.match(/\b([A-Za-z]{2,4})\s*[ _\-|#]\s*(\d{1,3})\b/)
        || line.match(/\b([A-Za-z]{2,4})(\d{1,3})\b/);
      if (!codeMatch) return;
      var name = line
        .replace(codeMatch[0], ' ')
        .replace(/^\s*\d+\s*[xX]?\s*/, ' ')
        .replace(/[()\[\]|,]/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
      if (name.length < 3) return;
      out.push({ name: name, set: codeMatch[1].toUpperCase(), number: codeMatch[2] });
    });
    return out;
  }

  // cards: [{ id, name }] - everything we could put art on.
  function importDeckNumbers(text, cards) {
    var entries = [];
    try { entries = collectFromJson(JSON.parse(text), [], 0); } catch (e) { /* not JSON */ }
    if (!entries.length) entries = collectFromText(text);

    var byName = {};
    entries.forEach(function (e) {
      var k = normName(e.name);
      if (k && !byName[k]) byName[k] = { set: e.set, number: e.number };
    });

    var numbers = {}, matched = [], unmatched = [];
    cards.forEach(function (c) {
      var hit = byName[normName(c.name)];
      if (hit) { numbers[c.id] = hit; matched.push(c.name); }
      else unmatched.push(c.name);
    });
    return { numbers: numbers, matched: matched, unmatched: unmatched, found: entries.length };
  }

  global.SWU_ART = {
    load: load, save: save, urlFor: urlFor, markFailed: markFailed,
    importDeckNumbers: importDeckNumbers, PRESETS: PRESETS,
    get config() { return config; }
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
