/* Star Wars Unlimited practice engine.
 *
 * Implements the two-player round structure (action phase / regroup phase),
 * resources, aspect penalties, attacking with arena + Sentinel restrictions,
 * shields, experience, and the keyword set this deck actually uses:
 * Raid, Sentinel, Saboteur, Ambush, Hidden.
 *
 * Choices go through g.prompt(side, spec, cb). Prompts for the AI side are
 * resolved immediately by SWU_AI.resolvePrompt; prompts for the human side
 * park in g.pending until the UI calls g.resolvePending(ids).
 */
(function (global) {
  'use strict';

  var nextUid = 0;
  function uid() { return 'c' + (++nextUid); }

  function mulberry32(seed) {
    return function () {
      seed |= 0; seed = seed + 0x6D2B79F5 | 0;
      var t = Math.imul(seed ^ seed >>> 15, 1 | seed);
      t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
      return ((t ^ t >>> 14) >>> 0) / 4294967296;
    };
  }

  function Card(def, owner) {
    this.uid = uid();
    this.def = def;
    this.owner = owner;
    this.controller = owner;
    this.zone = 'deck';
    this.damage = 0;
    this.exhausted = false;
    this.upgrades = [];      // [{name, power, hp, shield?, experience?}]
    this.playedRound = 0;
    this.usedThisRound = false;
    this.tempPower = 0;
    this.resourcesPaid = 0;
  }
  Card.prototype.bonus = function (key) {
    return this.upgrades.reduce(function (a, u) { return a + (u[key] || 0); }, 0);
  };
  Card.prototype.power = function () {
    return Math.max(0, (this.def.power || 0) + this.bonus('power') + (this.tempPower || 0));
  };
  Card.prototype.hp = function () { return (this.def.hp || 0) + this.bonus('hp'); };
  Card.prototype.remainingHp = function () { return this.hp() - this.damage; };
  Card.prototype.shields = function () {
    return this.upgrades.filter(function (u) { return u.shield; }).length;
  };
  Card.prototype.kw = function (name) {
    var k = this.def.keywords || {};
    return k[name];
  };

  function Base(def, owner) {
    this.uid = uid();
    this.def = def;
    this.owner = owner;
    this.controller = owner;
    this.isBase = true;
    this.damage = 0;
  }
  Base.prototype.remainingHp = function () { return this.def.hp - this.damage; };

  function buildDeck(defs, owner) {
    var out = [];
    defs.forEach(function (d) {
      for (var i = 0; i < (d.qty || 1); i++) out.push(new Card(d, owner));
    });
    return out;
  }

  // =========================================================================
  function Game(options) {
    options = options || {};
    this.rng = mulberry32(options.seed == null ? (Math.random() * 1e9) | 0 : options.seed);
    this.logLines = [];
    this.pending = null;
    this.actionInProgress = false;
    this.winner = null;
    this.round = 0;
    this.phase = 'setup';
    this.passed = { you: false, ai: false };
    this.initiativeClaimedBy = null;

    var mine = global.SWU_CARDS, theirs = global.SWU_OPPONENT;
    this.players = {
      you: this.makePlayer('you', mine, options.youFirst),
      ai: this.makePlayer('ai', theirs, false)
    };
    this.initiative = options.youFirst == null
      ? (this.rng() < 0.5 ? 'you' : 'ai')
      : (options.youFirst ? 'you' : 'ai');
    this.activePlayer = this.initiative;
  }

  Game.prototype.makePlayer = function (side, set, _first) {
    var leader = new Card(set.LEADER, side);
    leader.zone = 'leader';
    leader.isLeader = true;
    leader.deployed = false;
    return {
      side: side,
      name: side === 'you' ? 'You' : 'Opponent',
      deckName: set.DECK_NAME,
      leader: leader,
      base: new Base(set.BASE, side),
      deck: buildDeck(set.DECK, side),
      hand: [],
      discard: [],
      units: [],
      resources: [],           // [{exhausted:bool}]
      credits: 0,
      epicUsed: { leader: false, base: false },
      discardedThisPhase: 0
    };
  };

  // ----------------------------------------------------------------- basics
  Game.prototype.player = function (side) { return this.players[side]; };
  Game.prototype.other = function (side) { return side === 'you' ? 'ai' : 'you'; };
  Game.prototype.name = function (side) { return this.players[side].name; };
  Game.prototype.log = function (msg) {
    this.logLines.push({ round: this.round, text: msg });
    if (this.logLines.length > 400) this.logLines.shift();
  };
  // "You play ..." / "Opponent plays ..."
  Game.prototype.says = function (side, verb) {
    return this.name(side) + ' ' + (side === 'you' ? verb : verb + (/(s|sh|ch|x)$/.test(verb) ? 'es' : 's'));
  };
  Game.prototype.cardLabel = function (c) {
    var d = c.def;
    if (d.type === 'unit') return d.name + ' (' + d.cost + ') ' + d.power + '/' + d.hp;
    return d.name + ' (' + d.cost + ')';
  };
  Game.prototype.asOptions = function (list) {
    var g = this;
    return list.map(function (t) {
      if (t.isBase) return { id: t.uid, label: g.name(t.owner) + "'s base (" + t.remainingHp() + ' HP left)' };
      return { id: t.uid, label: (t.controller === 'you' ? 'Your ' : "Opponent's ") + t.def.name +
        ' [' + t.remainingHp() + ' HP]' };
    });
  };

  Game.prototype.shuffleDeck = function (side) {
    var d = this.players[side].deck;
    for (var i = d.length - 1; i > 0; i--) {
      var j = Math.floor(this.rng() * (i + 1));
      var t = d[i]; d[i] = d[j]; d[j] = t;
    }
  };

  Game.prototype.findUnit = function (id) {
    var found = null;
    for (var s in this.players) {
      var p = this.players[s];
      for (var i = 0; i < p.units.length; i++) if (p.units[i].uid === id) return p.units[i];
      if (p.base.uid === id) return p.base;
      if (p.leader.uid === id) return p.leader;
    }
    return found;
  };

  Game.prototype.targets = function (side, filter) {
    var out = [], g = this, opp = this.other(side);
    function keep(u) { return !filter.arena || u.def.arena === filter.arena; }
    if (filter.enemyUnits) this.players[opp].units.filter(keep).forEach(function (u) { out.push(u); });
    if (filter.friendlyUnits) this.players[side].units.filter(keep).forEach(function (u) { out.push(u); });
    if (filter.bases) { out.push(this.players[opp].base); out.push(this.players[side].base); }
    return out;
  };

  // -------------------------------------------------------------- resources
  Game.prototype.readyResources = function (p) {
    return p.resources.filter(function (r) { return !r.exhausted; }).length;
  };
  Game.prototype.canPay = function (p, cost) {
    return this.readyResources(p) + p.credits >= cost;
  };
  Game.prototype.pay = function (p, cost) {
    var paid = 0;
    for (var i = 0; i < p.resources.length && paid < cost; i++) {
      if (!p.resources[i].exhausted) { p.resources[i].exhausted = true; paid++; }
    }
    while (paid < cost && p.credits > 0) { p.credits--; paid++; }
    return paid;
  };

  // Extra cost for aspect icons not covered by leader + base (2 per icon).
  Game.prototype.aspectPenalty = function (side, card) {
    var p = this.players[side];
    var covered = (p.leader.def.aspects || []).concat(p.base.def.aspects || []).slice();
    var penalty = 0;
    (card.def.aspects || []).forEach(function (a) {
      var idx = covered.indexOf(a);
      if (idx >= 0) covered.splice(idx, 1); else penalty += 2;
    });
    return penalty;
  };
  Game.prototype.costOf = function (side, card, discount) {
    var c = card.def.cost + this.aspectPenalty(side, card) - (discount || 0);
    return Math.max(0, c);
  };
  Game.prototype.canAfford = function (side, card, discount) {
    return this.canPay(this.players[side], this.costOf(side, card, discount || 0));
  };

  // ----------------------------------------------------------------- prompts
  Game.prototype.prompt = function (side, spec, cb) {
    var g = this;
    spec = spec || {};
    if (!spec.options || !spec.options.length) {
      if (spec.optional) { cb([]); return; }
      cb([]); return;
    }
    var entry = { side: side, text: spec.text, options: spec.options,
                  optional: !!spec.optional, multi: !!spec.multi, hint: spec.hint || '', cb: cb };
    if (side === 'ai' && global.SWU_AI && global.SWU_AI.resolvePrompt) {
      var picked = global.SWU_AI.resolvePrompt(this, entry);
      cb(picked || []);
      return;
    }
    // Queue for the human. Only one prompt can be open at a time; nested
    // prompts are created from inside the callback, so this is safe.
    this.pending = entry;
  };

  Game.prototype.resolvePending = function (ids) {
    if (!this.pending) return;
    var entry = this.pending;
    this.pending = null;
    entry.cb(ids || []);
    this.settle();
  };

  // Called after any action/prompt chain to finish the turn once nothing is
  // waiting on a choice.
  Game.prototype.settle = function () {
    this.checkWinner();
    if (this.pending || this.winner) return;
    if (this.actionInProgress) {
      this.actionInProgress = false;
      this.endTurn();
    }
  };

  // ------------------------------------------------------------------ cards
  Game.prototype.draw = function (side, n) {
    var p = this.players[side];
    for (var i = 0; i < n; i++) {
      if (!p.deck.length) {
        // Empty deck: the player deals 3 damage to their own base instead.
        p.base.damage += 3;
        this.log(this.name(side) + ' cannot draw — 3 damage to their own base.');
        this.checkWinner();
        continue;
      }
      var c = p.deck.shift();
      c.zone = 'hand';
      p.hand.push(c);
    }
  };

  Game.prototype.discardFromHand = function (side, card) {
    var p = this.players[side];
    var i = p.hand.indexOf(card);
    if (i < 0) return;
    p.hand.splice(i, 1);
    card.zone = 'discard';
    card.discardedPhase = this.phaseSerial();
    p.discard.push(card);
    p.discardedThisPhase++;
    this.log(this.says(side, 'discard') + ' ' + card.def.name + ' from hand.');
  };

  Game.prototype.discardFromDeck = function (side, card) {
    var p = this.players[side];
    var i = p.deck.indexOf(card);
    if (i < 0) return;
    p.deck.splice(i, 1);
    card.zone = 'discard';
    card.discardedPhase = this.phaseSerial();
    p.discard.push(card);
    p.discardedThisPhase++;
    this.log(this.says(side, 'discard') + ' ' + card.def.name + ' from their deck.');
    this.triggerDeckDiscard(side);
  };

  Game.prototype.triggerDeckDiscard = function (side) {
    var g = this;
    this.players[side].units.slice().forEach(function (u) {
      if (u.def.onOwnerDeckDiscard) u.def.onOwnerDeckDiscard(g, u);
    });
  };

  Game.prototype.phaseSerial = function () { return this.round * 10 + (this.phase === 'action' ? 1 : 2); };

  Game.prototype.returnToHand = function (id) {
    var unit = this.findUnit(id);
    if (!unit || unit.isBase || unit.isLeader) return;
    var p = this.players[unit.controller];
    var i = p.units.indexOf(unit);
    if (i < 0) return;
    p.units.splice(i, 1);
    unit.damage = 0; unit.upgrades = []; unit.exhausted = false; unit.tempPower = 0;
    unit.zone = 'hand';
    this.players[unit.owner].hand.push(unit);
    this.log(unit.def.name + ' returns to ' + this.name(unit.owner) + "'s hand.");
  };

  Game.prototype.returnFromDiscardToHand = function (side, id) {
    var p = this.players[side];
    for (var i = 0; i < p.discard.length; i++) {
      if (p.discard[i].uid === id) {
        var c = p.discard.splice(i, 1)[0];
        c.zone = 'hand';
        p.hand.push(c);
        this.log(this.says(side, 'return') + ' ' + c.def.name + ' to hand.');
        return;
      }
    }
  };

  Game.prototype.changeControl = function (unit, newSide) {
    var from = this.players[unit.controller], to = this.players[newSide];
    var i = from.units.indexOf(unit);
    if (i < 0) return;
    from.units.splice(i, 1);
    unit.controller = newSide;
    to.units.push(unit);
    this.log(this.says(newSide, 'take') + ' control of ' + unit.def.name + '.');
  };

  Game.prototype.addShield = function (card) {
    card.upgrades.push({ name: 'Shield', shield: true, power: 0, hp: 0 });
  };
  Game.prototype.addExperience = function (card) {
    card.upgrades.push({ name: 'Experience', experience: true, power: 1, hp: 1 });
  };

  // ----------------------------------------------------------------- damage
  Game.prototype.damage = function (target, amount, source) {
    if (typeof target === 'string') target = this.findUnit(target);
    if (!target || amount <= 0) return;
    if (!target.isBase && target.shields() > 0) {
      for (var i = 0; i < target.upgrades.length; i++) {
        if (target.upgrades[i].shield) { target.upgrades.splice(i, 1); break; }
      }
      this.log(target.def.name + "'s Shield absorbs the damage.");
      return;
    }
    target.damage += amount;
    this.log(amount + ' damage to ' +
      (target.isBase ? this.name(target.owner) + "'s base" : target.def.name) +
      (target.isBase ? ' (' + Math.max(0, target.remainingHp()) + ' HP left)' : ''));
    if (!target.isBase) this.checkDefeat(target);
    this.checkWinner();
  };

  Game.prototype.checkDefeat = function (unit) {
    if (unit.isBase || unit.remainingHp() > 0) return;
    var p = this.players[unit.controller];
    var i = p.units.indexOf(unit);
    if (i < 0) return;
    p.units.splice(i, 1);
    this.log(unit.def.name + ' is defeated.');
    var owner = this.players[unit.owner];
    if (unit.isLeader) {
      // A defeated leader goes back to the leader zone, undeployed.
      unit.deployed = false;
      unit.damage = 0;
      unit.upgrades = [];
      unit.exhausted = true;
      unit.zone = 'leader';
      this.log(unit.def.name + ' returns to the leader zone (undeployed).');
    } else {
      unit.zone = 'discard';
      unit.damage = 0;
      unit.upgrades = [];
      unit.tempPower = 0;
      owner.discard.push(unit);
    }
    if (unit.def.onDefeated) unit.def.onDefeated(this, unit);
  };

  Game.prototype.checkWinner = function () {
    if (this.winner) return;
    var youDead = this.players.you.base.remainingHp() <= 0;
    var aiDead = this.players.ai.base.remainingHp() <= 0;
    if (youDead && aiDead) this.winner = 'draw';
    else if (aiDead) this.winner = 'you';
    else if (youDead) this.winner = 'ai';
    if (this.winner) {
      this.pending = null;
      this.actionInProgress = false;
      this.log(this.winner === 'draw' ? 'Both bases are destroyed — a draw.'
        : this.name(this.winner) + ' win' + (this.winner === 'you' ? '' : 's') + ' the game!');
    }
  };

  // ------------------------------------------------------------------ setup
  Game.prototype.start = function () {
    var g = this;
    this.round = 1;
    this.phase = 'setup';
    ['you', 'ai'].forEach(function (s) {
      g.shuffleDeck(s);
      g.draw(s, 6);
    });
    this.log('Game start. ' + this.name(this.initiative) + ' ' +
      (this.initiative === 'you' ? 'have' : 'has') + ' the initiative.');
    this.mulliganStep('ai', function () {
      g.mulliganStep('you', function () {
        g.initialResourceStep('ai', function () {
          g.initialResourceStep('you', function () {
            g.phase = 'action';
            g.log('--- Round 1: action phase. ' + g.name(g.activePlayer) + ' to act. ---');
          });
        });
      });
    });
  };

  Game.prototype.mulliganStep = function (side, done) {
    var g = this, p = this.players[side];
    this.prompt(side, {
      text: 'Mulligan? (Shuffle your hand back and draw 6 new cards — once only.)',
      optional: true, hint: 'mulligan',
      options: [{ id: 'yes', label: 'Mulligan this hand' }]
    }, function (picked) {
      if (picked.length) {
        p.hand.forEach(function (c) { c.zone = 'deck'; p.deck.push(c); });
        p.hand = [];
        g.shuffleDeck(side);
        g.draw(side, 6);
        g.log(g.says(side, 'mulligan') + '.');
      }
      done();
    });
  };

  Game.prototype.initialResourceStep = function (side, done) {
    var g = this, p = this.players[side];
    function pick(n) {
      if (n === 0) { done(); return; }
      g.prompt(side, {
        text: 'Choose a card to put into your resource row (' + n + ' left)',
        optional: false, hint: 'resource',
        options: p.hand.map(function (c) { return { id: c.uid, label: g.cardLabel(c) }; })
      }, function (picked) {
        var c = p.hand.filter(function (x) { return x.uid === picked[0]; })[0] || p.hand[0];
        g.resourceCard(side, c);
        pick(n - 1);
      });
    }
    pick(2);
  };

  Game.prototype.resourceCard = function (side, card) {
    var p = this.players[side];
    var i = p.hand.indexOf(card);
    if (i < 0) return;
    p.hand.splice(i, 1);
    card.zone = 'resource';
    p.resources.push({ exhausted: false, card: card });
    this.log(this.says(side, 'resource') + ' a card (' + p.resources.length + ' total).');
  };

  // ----------------------------------------------------------------- actions
  Game.prototype.legalActions = function (side) {
    if (this.winner || this.phase !== 'action' || this.activePlayer !== side) return [];
    var g = this, p = this.players[side], acts = [];

    p.hand.forEach(function (c) {
      if (g.canAfford(side, c, 0)) {
        acts.push({ kind: 'play', cardUid: c.uid,
          label: 'Play ' + g.cardLabel(c) + ' — ' + g.costOf(side, c, 0) });
      }
    });

    // Salvaged Blaster-style replay from discard.
    p.discard.forEach(function (c) {
      if (c.def.playableFromDiscard && c.discardedPhase === g.phaseSerial() && g.canAfford(side, c, 0)) {
        acts.push({ kind: 'play-discard', cardUid: c.uid,
          label: 'Play ' + c.def.name + ' from discard — ' + g.costOf(side, c, 0) });
      }
    });

    p.units.forEach(function (u) {
      if (u.exhausted) return;
      if (!g.attackTargets(u).length) return;
      acts.push({ kind: 'attack', cardUid: u.uid, label: 'Attack with ' + u.def.name });
    });

    var la = p.leader.def.leaderAction;
    if (la && la.usable(this, side)) acts.push({ kind: 'leader-action', label: la.label });

    if (!p.leader.deployed) {
      var epic = p.leader.def.epicDeploy;
      if (epic && !p.epicUsed.leader && epic.usable(this, side)) {
        acts.push({ kind: 'epic-deploy', label: epic.label });
      }
      if (g.canPay(p, p.leader.def.cost)) {
        acts.push({ kind: 'deploy', label: 'Deploy ' + p.leader.def.name + ' — ' + p.leader.def.cost });
      }
    }

    if (!this.initiativeClaimedBy) {
      acts.push({ kind: 'initiative', label: 'Take the initiative' });
    }

    acts.push({ kind: 'pass', label: 'Pass' });
    return acts;
  };

  Game.prototype.doAction = function (side, action) {
    if (this.winner || this.pending) return;
    if (this.phase !== 'action' || this.activePlayer !== side) return;
    this.actionInProgress = true;
    var p = this.players[side];

    switch (action.kind) {
      case 'play': {
        var card = p.hand.filter(function (c) { return c.uid === action.cardUid; })[0];
        if (card) this.playCard(side, card, {});
        break;
      }
      case 'play-discard': {
        var dcard = p.discard.filter(function (c) { return c.uid === action.cardUid; })[0];
        if (dcard) {
          var di = p.discard.indexOf(dcard);
          p.discard.splice(di, 1);
          p.hand.push(dcard);
          this.playCard(side, dcard, {});
        }
        break;
      }
      case 'attack': {
        var unit = this.findUnit(action.cardUid);
        if (unit) this.beginAttack(unit, {});
        break;
      }
      case 'leader-action':
        p.leader.def.leaderAction.use(this, side);
        break;
      case 'deploy':
        this.pay(p, p.leader.def.cost);
        this.deployLeader(side);
        break;
      case 'epic-deploy':
        p.epicUsed.leader = true;
        this.log(this.name(side) + ' uses an Epic Action.');
        this.deployLeader(side);
        break;
      case 'initiative':
        this.initiativeClaimedBy = side;
        this.initiative = side;
        this.log(this.name(side) + ' take' + (side === 'you' ? '' : 's') + ' the initiative.');
        break;
      case 'pass':
        this.passed[side] = true;
        this.log(this.name(side) + ' pass' + (side === 'you' ? '' : 'es') + '.');
        break;
    }
    if (action.kind !== 'pass') this.passed[side] = false;
    this.settle();
  };

  Game.prototype.playCard = function (side, card, opts) {
    opts = opts || {};
    var p = this.players[side];
    var cost = this.costOf(side, card, opts.discount || 0);
    var paid = opts.free ? 0 : this.pay(p, cost);
    card.resourcesPaid = paid;
    var i = p.hand.indexOf(card);
    if (i >= 0) p.hand.splice(i, 1);
    this.log(this.says(side, 'play') + ' ' + card.def.name + ' for ' + (opts.free ? 0 : cost) + '.');

    if (card.def.type === 'unit') {
      card.zone = 'play';
      card.controller = side;
      card.damage = 0;
      card.upgrades = [];
      card.tempPower = 0;
      card.exhausted = true;              // units enter play exhausted
      card.playedRound = this.round;
      card.usedThisRound = false;
      p.units.push(card);
      if (card.def.onPlay) card.def.onPlay(this, card, side);
      if (card.kw('ambush')) this.ambush(card);
    } else if (card.def.type === 'upgrade') {
      card.zone = 'discard';
      if (card.def.onPlay) card.def.onPlay(this, card, side);
      // The upgrade itself is tracked as an attachment on the unit; the physical
      // card leaves play only when that attachment is defeated, which this app
      // models by discarding the card object now.
      p.discard.push(card);
    } else {
      card.zone = 'discard';
      if (card.def.onPlay) card.def.onPlay(this, card, side);
      p.discard.push(card);
    }
  };

  Game.prototype.ambush = function (card) {
    var g = this;
    var enemies = this.players[this.other(card.controller)].units
      .filter(function (u) { return u.def.arena === card.def.arena && !g.isHidden(u); });
    if (!enemies.length) { card.exhausted = false; g.log(card.def.name + ' (Ambush) readies.'); return; }
    this.prompt(card.controller, {
      text: 'Ambush: ready ' + card.def.name + ' and attack an enemy unit?',
      optional: true, hint: 'ambush', options: this.asOptions(enemies)
    }, function (picked) {
      card.exhausted = false;
      if (!picked.length) { g.log(card.def.name + ' (Ambush) readies.'); return; }
      g.beginAttack(card, {}, picked[0]);
    });
  };

  Game.prototype.deployLeader = function (side) {
    var p = this.players[side], l = p.leader;
    l.deployed = true;
    l.zone = 'play';
    l.controller = side;
    l.damage = 0;
    l.upgrades = [];
    l.exhausted = true;
    l.playedRound = this.round;
    p.units.push(l);
    this.log(this.says(side, 'deploy') + ' ' + l.def.name + ' (' + l.def.power + '/' + l.def.hp + ').');
  };

  // ---------------------------------------------------------------- attacks
  Game.prototype.isHidden = function (unit) {
    return !!(unit.kw && unit.kw('hidden') && unit.playedRound === this.round);
  };

  Game.prototype.attackTargets = function (attacker, mods) {
    mods = mods || {};
    var g = this;
    var opp = this.players[this.other(attacker.controller)];
    var arena = attacker.def.arena;
    var units = opp.units.filter(function (u) {
      return u.def.arena === arena && !g.isHidden(u);
    });
    var saboteur = attacker.kw('saboteur') || mods.saboteur;
    if (!saboteur) {
      var sentinels = units.filter(function (u) { return u.kw('sentinel'); });
      if (sentinels.length) return sentinels;
    }
    return units.concat([opp.base]);
  };

  Game.prototype.beginAttack = function (attacker, mods, forcedTargetId) {
    var g = this;
    mods = mods || {};
    if (attacker.exhausted) { this.log(attacker.def.name + ' is exhausted and cannot attack.'); return; }
    var targets = this.attackTargets(attacker, mods);
    if (!targets.length) { this.log('No legal attack target for ' + attacker.def.name + '.'); return; }
    if (forcedTargetId) { this.resolveAttack(attacker, this.findUnit(forcedTargetId), mods); return; }
    this.prompt(attacker.controller, {
      text: 'Attack with ' + attacker.def.name + ' — choose a target',
      optional: false, hint: 'attack-target', options: this.asOptions(targets)
    }, function (picked) {
      var target = g.findUnit(picked[0]) || targets[0];
      g.resolveAttack(attacker, target, mods);
    });
  };

  Game.prototype.resolveAttack = function (attacker, target, mods) {
    var g = this;
    mods = mods || {};
    if (!target) return;
    attacker.exhausted = true;
    this.log(this.says(attacker.controller, 'attack') + ' ' +
      (target.isBase ? this.name(target.owner) + "'s base" : target.def.name) +
      ' with ' + attacker.def.name + '.');

    var finish = function () {
      if (attacker.zone !== 'play' && !attacker.isLeader) return;
      var power = attacker.power() + (mods.power || 0);
      if (target.isBase && attacker.kw('raid')) {
        power += attacker.kw('raid');
        g.log(attacker.def.name + ' has Raid ' + attacker.kw('raid') + ' (+' + attacker.kw('raid') + ' vs base).');
      }
      var saboteur = attacker.kw('saboteur') || mods.saboteur;
      if (saboteur && !target.isBase && target.shields() > 0) {
        target.upgrades = target.upgrades.filter(function (u) { return !u.shield; });
        g.log('Saboteur defeats all Shields on ' + target.def.name + '.');
      }
      var counter = target.isBase ? 0 : target.power();
      g.damage(target, power, attacker);
      if (counter > 0 && attacker.zone === 'play') g.damage(attacker, counter, target);
    };

    if (attacker.def.onAttack) {
      attacker.def.onAttack(this, attacker);
      // onAttack may have opened a prompt; queue the damage step behind it.
      if (this.pending) {
        var original = this.pending.cb;
        this.pending.cb = function (ids) { original(ids); if (!g.pending) finish(); };
        return;
      }
    }
    finish();
  };

  // ------------------------------------------------------------ turn / phase
  Game.prototype.endTurn = function () {
    if (this.winner) return;
    var other = this.other(this.activePlayer);
    if (this.passed.you && this.passed.ai) { this.regroup(); return; }
    // The opponent acts next unless they have already passed and we have not.
    if (this.passed[other] && !this.passed[this.activePlayer]) return; // keep acting
    this.activePlayer = other;
  };

  Game.prototype.regroup = function () {
    var g = this;
    this.phase = 'regroup';
    this.log('--- Round ' + this.round + ': regroup phase ---');
    ['you', 'ai'].forEach(function (s) { g.players[s].discardedThisPhase = 0; });

    var order = this.initiative === 'you' ? ['you', 'ai'] : ['ai', 'you'];
    this.regroupResource(order[0], function () {
      g.regroupResource(order[1], function () {
        ['you', 'ai'].forEach(function (s) {
          var p = g.players[s];
          g.draw(s, 2);
          p.resources.forEach(function (r) { r.exhausted = false; });
          p.units.forEach(function (u) { u.exhausted = false; u.usedThisRound = false; u.tempPower = 0; });
          p.leader.exhausted = false;
          p.leader.usedThisRound = false;
        });
        g.round++;
        g.phase = 'action';
        g.passed = { you: false, ai: false };
        g.initiativeClaimedBy = null;
        g.activePlayer = g.initiative;
        ['you', 'ai'].forEach(function (s) { g.players[s].discardedThisPhase = 0; });
        g.log('--- Round ' + g.round + ': action phase. ' + g.name(g.activePlayer) + ' to act. ---');
        g.checkWinner();
      });
    });
  };

  Game.prototype.regroupResource = function (side, done) {
    var g = this, p = this.players[side];
    if (!p.hand.length) { done(); return; }
    this.prompt(side, {
      text: 'Regroup: put a card into your resource row? (' + p.resources.length + ' resources now)',
      optional: true, hint: 'resource',
      options: p.hand.map(function (c) { return { id: c.uid, label: g.cardLabel(c) }; })
    }, function (picked) {
      if (picked.length) {
        var c = p.hand.filter(function (x) { return x.uid === picked[0]; })[0];
        if (c) g.resourceCard(side, c);
      }
      done();
    });
  };

  global.SWU_ENGINE = { Game: Game, Card: Card };
})(typeof globalThis !== 'undefined' ? globalThis : this);
