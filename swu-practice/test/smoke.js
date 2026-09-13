/* Fuzz harness: plays full games with a random-but-legal human side against the
 * heuristic AI, to catch crashes, stuck prompts and rounds that never end.
 *
 * Run: node test/smoke.js [games]
 */
'use strict';
var path = require('path');
['cards', 'opponent-deck', 'engine', 'ai'].forEach(function (f) {
  require(path.join(__dirname, '..', 'js', f + '.js'));
});

function rngFor(seed) {
  return function () {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed / 4294967296;
  };
}

function playGame(seed) {
  var rnd = rngFor(seed + 7);
  var g = new globalThis.SWU_ENGINE.Game({ seed: seed });
  g.start();

  var steps = 0;
  while (!g.winner && steps < 8000) {
    steps++;
    if (g.pending) {
      var p = g.pending;
      if (p.side === 'ai') { g.resolvePending(globalThis.SWU_AI.resolvePrompt(g, p)); continue; }
      var pick = [];
      if (p.multi) {
        p.options.forEach(function (o) { if (rnd() < 0.25) pick.push(o.id); });
      } else if (!p.optional || rnd() < 0.6) {
        pick = [p.options[Math.floor(rnd() * p.options.length)].id];
      }
      g.resolvePending(pick);
      continue;
    }
    if (g.activePlayer === 'ai') {
      if (!globalThis.SWU_AI.takeAction(g)) throw new Error('AI could not act at round ' + g.round);
      continue;
    }
    var acts = g.legalActions('you');
    if (!acts.length) throw new Error('No legal action for player at round ' + g.round);
    // Bias away from passing so games actually progress.
    var nonPass = acts.filter(function (a) { return a.kind !== 'pass'; });
    var pool = (nonPass.length && rnd() < 0.85) ? nonPass : acts;
    g.doAction('you', pool[Math.floor(rnd() * pool.length)]);
    if (g.round > 60) throw new Error('Game did not terminate by round 60');
  }
  if (steps >= 8000) throw new Error('Step limit hit (possible stuck prompt), round ' + g.round);
  return { winner: g.winner, rounds: g.round, steps: steps };
}

var n = Number(process.argv[2] || 200);
var tally = { you: 0, ai: 0, draw: 0 }, roundsTotal = 0, failures = [];
for (var s = 1; s <= n; s++) {
  try {
    var r = playGame(s);
    tally[r.winner]++;
    roundsTotal += r.rounds;
  } catch (e) {
    failures.push('seed ' + s + ': ' + e.message);
  }
}
console.log('games:', n);
console.log('results:', JSON.stringify(tally));
console.log('avg rounds:', (roundsTotal / Math.max(1, n - failures.length)).toFixed(1));
if (failures.length) {
  console.log('FAILURES (' + failures.length + '):');
  failures.slice(0, 10).forEach(function (f) { console.log('  ' + f); });
  process.exit(1);
}
console.log('OK — no crashes, all games terminated.');
