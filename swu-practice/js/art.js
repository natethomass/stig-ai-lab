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
  var config = { mode: 'off', template: '' };
  var failed = {};                       // urls that 404'd, so we stop retrying

  function load() {
    try {
      var raw = global.localStorage && global.localStorage.getItem(KEY);
      if (raw) {
        var parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object') {
          config.mode = parsed.mode || 'off';
          config.template = parsed.template || '';
        }
      }
    } catch (e) { /* private mode, blocked storage - stay on defaults */ }
    return config;
  }

  function save(next) {
    config.mode = next.mode || 'off';
    config.template = next.template || '';
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
      var set = (def.set || '').split(/\s+/)[0] || '';
      var number = (def.set || '').split(/\s+/)[1] || '';
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

  global.SWU_ART = {
    load: load, save: save, urlFor: urlFor, markFailed: markFailed,
    get config() { return config; }
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
