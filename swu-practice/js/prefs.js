/* Personal settings: your name on the board and the accent colour of the app.
 * Stored in localStorage, so they stick on whatever device you play on.
 */
(function (global) {
  'use strict';

  var KEY = 'swu-practice-prefs';

  var ACCENTS = [
    { id: 'gold',    name: 'Imperial Gold', value: '#f2b705' },
    { id: 'crimson', name: 'Sith Crimson',  value: '#e0483a' },
    { id: 'violet',  name: 'Villainy',      value: '#9d6bff' },
    { id: 'teal',    name: 'Cunning',       value: '#2fbfae' },
    { id: 'ice',     name: 'Ice Blue',      value: '#6cd0ff' }
  ];

  var prefs = { name: 'You', accent: 'gold' };

  function load() {
    try {
      var raw = global.localStorage && global.localStorage.getItem(KEY);
      if (raw) {
        var p = JSON.parse(raw);
        if (p && typeof p === 'object') {
          if (typeof p.name === 'string' && p.name.trim()) prefs.name = p.name.trim().slice(0, 24);
          if (accentById(p.accent)) prefs.accent = p.accent;
        }
      }
    } catch (e) { /* blocked storage - defaults are fine */ }
    apply();
    return prefs;
  }

  function save(next) {
    if (typeof next.name === 'string') prefs.name = next.name.trim().slice(0, 24) || 'You';
    if (accentById(next.accent)) prefs.accent = next.accent;
    try {
      global.localStorage && global.localStorage.setItem(KEY, JSON.stringify(prefs));
    } catch (e) { /* not fatal */ }
    apply();
    return prefs;
  }

  function accentById(id) {
    return ACCENTS.filter(function (a) { return a.id === id; })[0];
  }

  function apply() {
    var a = accentById(prefs.accent) || ACCENTS[0];
    if (global.document && global.document.documentElement) {
      global.document.documentElement.style.setProperty('--accent', a.value);
    }
  }

  global.SWU_PREFS = {
    load: load, save: save, apply: apply, ACCENTS: ACCENTS,
    get name() { return prefs.name; },
    get accent() { return prefs.accent; }
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
