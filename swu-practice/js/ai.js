/* Heuristic opponent.
 *
 * Two entry points:
 *   SWU_AI.takeAction(game)      - pick and perform one action on the AI's turn
 *   SWU_AI.resolvePrompt(g, p)   - answer a choice the engine asked the AI for
 *
 * The AI plays a straightforward sealed game: curve out, take profitable
 * trades, punch the base when nothing good is on the board, and claim the
 * initiative before it runs out of gas.
 */
(function (global) {
  'use strict';


  function board(g, side) {
    return g.player(side).units.reduce(function (a, u) { return a + u.power() + u.remainingHp(); }, 0);
  }

  // Would `attacker` kill `target` without dying itself?
  function tradeScore(g, attacker, target) {
    if (target.isBase) return 0;
    var kills = attacker.power() >= target.remainingHp();
    var dies = target.power() >= attacker.remainingHp();
    var mine = attacker.power() + attacker.remainingHp();
    var theirs = target.power() + target.remainingHp();
    if (kills && !dies) return 100 + theirs;
    if (kills && dies) return 40 + (theirs - mine);
    if (!kills && dies) return -60;
    return 5;                                  // chip damage
  }


  function chooseAction(g, ME) {
    ME = ME || 'ai';
    var acts = g.legalActions(ME);
    if (!acts.length) return null;
    var me = g.player(ME), foe = g.player(g.other(ME));

    function first(kind, pred) {
      for (var i = 0; i < acts.length; i++) {
        if (acts[i].kind === kind && (!pred || pred(acts[i]))) return acts[i];
      }
      return null;
    }

    // 1. Lethal on the enemy base?
    var attacks = acts.filter(function (a) { return a.kind === 'attack'; });
    for (var i = 0; i < attacks.length; i++) {
      var u = g.findUnit(attacks[i].cardUid);
      var targets = g.attackTargets(u);
      var canHitBase = targets.some(function (t) { return t.isBase; });
      var power = u.power() + (u.kw('raid') || 0);
      if (canHitBase && power >= foe.base.remainingHp()) return attacks[i];
    }

    // 2. A free leader deploy is always worth taking.
    var epic = first('epic-deploy');
    if (epic) return epic;

    // 3. Best attack by trade value.
    var bestAttack = null, bestScore = -Infinity;
    attacks.forEach(function (a) {
      var unit = g.findUnit(a.cardUid);
      var targets = g.attackTargets(unit);
      targets.forEach(function (t) {
        var s = t.isBase
          ? 20 + unit.power() + (unit.kw('raid') || 0)
          : tradeScore(g, unit, t);
        // Prefer clearing a board that is beating us.
        if (!t.isBase && board(g, g.other(ME)) > board(g, ME)) s += 15;
        if (s > bestScore) { bestScore = s; bestAttack = a; }
      });
    });

    // 4. Development: play the most expensive affordable card most rounds.
    // Never empty the hand while still short of resources - you must be able to
    // put a card into the resource row during every regroup phase.
    var mustHoldResource = me.hand.length <= 1 && me.resources.length < 10;
    var plays = mustHoldResource ? [] : acts.filter(function (a) { return a.kind === 'play'; });
    var bestPlay = null;
    plays.forEach(function (a) {
      var c = me.hand.filter(function (h) { return h.uid === a.cardUid; })[0];
      if (!c) return;
      var value = g.costOf(ME, c, 0) * 10;
      if (c.def.type === 'unit') value += 15;
      if (c.def.type === 'unit' && c.def.keywords && c.def.keywords.sentinel &&
          board(g, g.other(ME)) > board(g, ME)) value += 20;
      if (c.def.type === 'event' && !g.player(g.other(ME)).units.length &&
          (c.def.id === 'g-volley' || c.def.id === 'collateral-damage')) value = -1;
      if (c.def.id === 'you-hold-this' && !g.player(g.other(ME)).units.length) value = -1;
      if (!bestPlay || value > bestPlay.value) bestPlay = { action: a, value: value };
    });

    // Deploy the leader once it is affordable and the board is contested.
    var deploy = first('deploy');
    if (deploy && g.round >= 5 && me.resources.length >= me.leader.def.cost + 1) return deploy;

    if (bestPlay && bestPlay.value >= 45) return bestPlay.action;
    if (bestAttack && bestScore >= 40) return bestAttack;
    if (bestPlay) return bestPlay.action;
    if (bestAttack && bestScore > 0) return bestAttack;
    if (deploy) return deploy;

    // Vader's ping costs a card from hand, so never use it if that card is the
    // one holding open this round's resource drop.
    var leaderAct = first('leader-action');
    if (leaderAct && !mustHoldResource && me.units.length) return leaderAct;

    var init = first('initiative');
    if (init) return init;
    return first('pass');
  }

  function resolvePrompt(g, entry, side) {
    var ME = side || entry.side || 'ai';
    var opts = entry.options.map(function (o) { return o.id; });
    var me = g.player(ME);

    // At lower difficulties the AI sometimes makes a sloppy choice.
    if (ME === 'ai' && randomChance > 0 && entry.hint !== 'resource' && Math.random() < randomChance) {
      if (entry.optional && Math.random() < 0.5) return [];
      return [opts[Math.floor(Math.random() * opts.length)]];
    }

    switch (entry.hint) {
      case 'mulligan': {
        // Mulligan hands with fewer than two cards costing 3 or less.
        var cheap = me.hand.filter(function (c) { return c.def.cost <= 3; }).length;
        return cheap < 2 ? [opts[0]] : [];
      }
      case 'resource': {
        // Resource the least useful card: highest cost first, events before units.
        var best = null;
        entry.options.forEach(function (o) {
          var c = me.hand.filter(function (h) { return h.uid === o.id; })[0];
          if (!c) return;
          var score = c.def.cost * 2 + (c.def.type === 'event' ? 3 : 0);
          if (!best || score > best.score) best = { id: o.id, score: score };
        });
        return best ? [best.id] : [opts[0]];
      }
      case 'damage': {
        // Kill something if possible, otherwise hit the enemy base.
        var amount = parseInt((entry.text.match(/(\d+) damage/) || [0, 1])[1], 10) || 1;
        var kill = null, chip = null, base = null;
        entry.options.forEach(function (o) {
          var t = g.findUnit(o.id);
          if (!t) return;
          if (t.isBase) { if (t.owner !== ME) base = o.id; return; }
          if (t.controller === ME) return;                    // never shoot our own
          if (t.remainingHp() <= amount && !kill) kill = o.id;
          if (!chip) chip = o.id;
        });
        var pick = kill || base || chip;
        return pick ? [pick] : (entry.optional ? [] : [opts[0]]);
      }
      case 'attack-target': {
        var attacker = null;
        // Recover the attacker from the prompt text.
        var m = entry.text.match(/Attack with (.+) —/);
        if (m) {
          attacker = me.units.filter(function (u) { return u.def.name === m[1]; })[0];
        }
        var best = null, bestScore = -Infinity;
        entry.options.forEach(function (o) {
          var t = g.findUnit(o.id);
          if (!t || !attacker) return;
          var s = t.isBase ? 20 + attacker.power() + (attacker.kw('raid') || 0)
                           : tradeScore(g, attacker, t);
          if (s > bestScore) { bestScore = s; best = o.id; }
        });
        return [best || opts[0]];
      }
      case 'hand-discard': {
        // Pitch the card we are least likely to cast.
        var worstCard = null;
        entry.options.forEach(function (o) {
          var c = me.hand.filter(function (h) { return h.uid === o.id; })[0];
          if (!c) return;
          var v = g.costOf(ME, c, 0);
          if (!worstCard || v > worstCard.v) worstCard = { id: o.id, v: v };
        });
        return worstCard ? [worstCard.id] : [opts[0]];
      }
      case 'may-pay':
        return g.canPay(me, 1) ? [opts[0]] : [];
      case 'ambush':
      case 'attacker':
        return [opts[0]];
      case 'give-away': {
        // Hand over the least valuable body (ideally a 0-power chump).
        var worst = null;
        entry.options.forEach(function (o) {
          var u = g.findUnit(o.id);
          if (!u || u.isBase) return;
          var v = u.power() * 2 + u.remainingHp();
          if (!worst || v < worst.v) worst = { id: o.id, v: v };
        });
        return worst ? [worst.id] : [opts[0]];
      }
      case 'bounce-friendly':
        return entry.optional ? [] : [opts[0]];
      default:
        return entry.optional ? [] : [opts[0]];
    }
  }

  // Difficulty is a single honest knob: how often the AI takes a random legal
  // action instead of its best one. No hidden bonuses either way.
  var DIFFICULTY = { padawan: 0.40, standard: 0.15, sith: 0 };
  var randomChance = DIFFICULTY.standard;
  function setDifficulty(name) {
    randomChance = DIFFICULTY[name] == null ? DIFFICULTY.standard : DIFFICULTY[name];
  }

  function takeAction(g, side) {
    var ME = side || 'ai';
    if (g.winner) return false;
    if (g.pending && g.pending.side === ME) {
      g.resolvePending(resolvePrompt(g, g.pending, ME));
      return true;
    }
    if (g.phase !== 'action' || g.activePlayer !== ME) return false;
    var action = chooseAction(g, ME);
    if (!action) return false;
    if (ME === 'ai' && randomChance > 0 && Math.random() < randomChance) {
      var all = g.legalActions(ME).filter(function (a) { return a.kind !== 'pass'; });
      if (all.length) action = all[Math.floor(Math.random() * all.length)];
    }
    g.doAction(ME, action);
    return true;
  }

  global.SWU_AI = {
    takeAction: takeAction, resolvePrompt: resolvePrompt, chooseAction: chooseAction,
    setDifficulty: setDifficulty, DIFFICULTY: DIFFICULTY
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
