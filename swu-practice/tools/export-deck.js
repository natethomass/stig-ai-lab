#!/usr/bin/env node
/* Write the deck out as files a deckbuilder can import.
 *
 *   dist/deck.txt   plain text, one "<count> <name>" line per card - the format
 *                   name-matching importers accept
 *   dist/deck.json  JSON in the shape SWU deckbuilders use, with names and
 *                   counts filled in. The id fields stay empty because this
 *                   decklist carries no collector numbers; an importer that
 *                   requires ids will need the text file instead.
 *
 * Generated from js/cards.js, so it always matches what the app actually plays.
 */
'use strict';
var fs = require('fs');
var path = require('path');

var ROOT = path.join(__dirname, '..');
require(path.join(ROOT, 'js/cards.js'));
var SET = globalThis.SWU_CARDS;

var leader = SET.LEADER, base = SET.BASE;
var entries = SET.DECK.map(function (d) {
  return { name: d.name, count: d.qty || 1, type: d.type };
});
var total = entries.reduce(function (a, e) { return a + e.count; }, 0);

// ---------------------------------------------------------------- deck.txt
var lines = [];
lines.push('Leader: ' + leader.name + ' - ' + leader.subtitle);
lines.push('Base: ' + base.name);
lines.push('');
entries.forEach(function (e) { lines.push(e.count + ' ' + e.name); });
var txt = lines.join('\n') + '\n';

// --------------------------------------------------------------- deck.json
var json = {
  metadata: { name: SET.DECK_NAME, author: '' },
  leader: { id: '', name: leader.name, subtitle: leader.subtitle, count: 1 },
  base: { id: '', name: base.name, count: 1 },
  deck: entries.map(function (e) { return { id: '', name: e.name, count: e.count }; }),
  sideboard: []
};

var dist = path.join(ROOT, 'dist');
fs.mkdirSync(dist, { recursive: true });
fs.writeFileSync(path.join(dist, 'deck.txt'), txt);
fs.writeFileSync(path.join(dist, 'deck.json'), JSON.stringify(json, null, 2) + '\n');

if (total !== 30) throw new Error('expected 30 cards, generated ' + total);
console.log('dist/deck.txt and dist/deck.json — ' + total + ' cards, ' +
  entries.length + ' unique, plus leader and base');
