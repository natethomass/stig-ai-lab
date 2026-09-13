/* AI-vs-AI balance check: both sides played by the same heuristic, to see how
 * the Vader deck fares against the sparring deck and how long games run.
 *
 * Run: node test/balance.js [games]
 */
'use strict';
var path = require('path');
['cards', 'opponent-deck', 'engine', 'ai'].forEach(function (f) {
  require(path.join(__dirname, '..', 'js', f + '.js'));
});

var n = Number(process.argv[2] || 200);
var tally = { you: 0, ai: 0, draw: 0, unfinished: 0 }, rounds = 0, fails = [];
for (var s = 1; s <= n; s++) {
  try {
    var g = new globalThis.SWU_ENGINE.Game({ seed: s, youFirst: s % 2 === 0 });
    g.start();
    var steps = 0;
    while (!g.winner && steps++ < 8000 && g.round <= 40) {
      if (g.pending) { g.resolvePending(globalThis.SWU_AI.resolvePrompt(g, g.pending, g.pending.side)); continue; }
      if (!globalThis.SWU_AI.takeAction(g, g.activePlayer)) {
        throw new Error('no action for ' + g.activePlayer + ' at round ' + g.round);
      }
    }
    if (!g.winner) tally.unfinished++; else { tally[g.winner]++; rounds += g.round; }
  } catch (e) { fails.push('seed ' + s + ': ' + e.message); }
}
console.log('games:', n, JSON.stringify(tally));
console.log('Vader deck win rate:', (100 * tally.you / Math.max(1, tally.you + tally.ai)).toFixed(1) + '%');
console.log('avg rounds:', (rounds / Math.max(1, tally.you + tally.ai)).toFixed(1));
if (fails.length) { fails.slice(0, 5).forEach(function (f) { console.log('  ' + f); }); process.exit(1); }
