/* Card definitions for the Vader Sealed practice app.
 *
 * A card definition is plain data plus optional hook functions. Hooks receive
 * (g, card) where g is the Game and card is the in-play instance, and they use
 * g.prompt(...) for any choice the controller has to make.
 */
(function (global) {
  'use strict';

  var AGG = 'Aggression', VIL = 'Villainy', CUN = 'Cunning',
      CMD = 'Command', VIG = 'Vigilance', HER = 'Heroism';

  // ---------------------------------------------------------------- helpers
  // Shared hook bodies, so the card table below stays readable.

  function mayPayThenDamage(payAmount, amount, filter, text) {
    return function (g, card) {
      var p = g.player(card.controller);
      if (!g.canPay(p, payAmount)) return;
      var targets = g.targets(card.controller, filter);
      if (!targets.length) return;
      g.prompt(card.controller, {
        text: text, optional: true, hint: 'damage',
        options: g.asOptions(targets)
      }, function (picked) {
        if (!picked.length) return;
        g.pay(p, payAmount);
        g.damage(picked[0], amount, card);
      });
    };
  }

  function damageTarget(amount, filter, text, optional) {
    return function (g, card) {
      var targets = g.targets(card.controller, filter);
      if (!targets.length) return;
      g.prompt(card.controller, {
        text: text, optional: !!optional, hint: 'damage',
        options: g.asOptions(targets)
      }, function (picked) {
        if (picked.length) g.damage(picked[0], amount, card);
      });
    };
  }

  // Look at top 3, may discard 1 (Qui-Gon).
  function lookTop3Discard1(g, card) {
    var p = g.player(card.controller);
    var top = p.deck.slice(0, 3);
    if (!top.length) return;
    g.prompt(card.controller, {
      text: 'Top ' + top.length + ' of your deck — you may discard 1',
      optional: true, hint: 'deck-discard',
      options: top.map(function (c) { return { id: c.uid, label: g.cardLabel(c) }; })
    }, function (picked) {
      if (!picked.length) return;
      var c = p.deck.filter(function (x) { return x.uid === picked[0]; })[0];
      g.discardFromDeck(card.controller, c);
    });
  }

  // Arvel Skeen: defeat a Credit token -> 1 damage to a unit or base.
  function spendCreditForDamage(g, card) {
    var p = g.player(card.controller);
    if (p.credits < 1) return;
    var targets = g.targets(card.controller, { enemyUnits: true, friendlyUnits: true, bases: true });
    if (!targets.length) return;
    g.prompt(card.controller, {
      text: 'Defeat a Credit token to deal 1 damage?', optional: true, hint: 'damage',
      options: g.asOptions(targets)
    }, function (picked) {
      if (!picked.length) return;
      p.credits -= 1;
      g.log(g.says(card.controller, 'defeat') + ' a Credit token.');
      g.damage(picked[0], 1, card);
    });
  }

  function defeatUpgradeOnSpaceUnit(g, card) {
    var upgrades = [];
    ['you', 'ai'].forEach(function (side) {
      g.player(side).units.forEach(function (u) {
        if (u.def.arena !== 'space') return;
        u.upgrades.forEach(function (up, i) {
          upgrades.push({ id: u.uid + ':' + i, label: up.name + ' on ' + u.def.name });
        });
      });
    });
    if (!upgrades.length) return;
    g.prompt(card.controller, {
      text: 'You may defeat an upgrade on a space unit', optional: true, hint: 'enemy-upgrade',
      options: upgrades
    }, function (picked) {
      if (!picked.length) return;
      var parts = picked[0].split(':');
      var unit = g.findUnit(parts[0]);
      if (!unit) return;
      var up = unit.upgrades.splice(Number(parts[1]), 1)[0];
      if (up) g.log(up.name + ' on ' + unit.def.name + ' is defeated.');
    });
  }

  // ------------------------------------------------------------- the leader
  var LEADER = {
    id: 'law011', name: 'Darth Vader', subtitle: 'Unstoppable', set: 'LAW 011',
    cost: 7, power: 6, hp: 8, arena: 'ground', aspects: [AGG, VIL],
    traits: ['Force', 'Imperial', 'Sith'],
    text: 'Action [exhaust, discard a card from hand]: Deal 1 damage to a unit or base. ' +
          'Epic Action: If you control 7+ resources, deploy this leader. ' +
          'Deployed On Attack: Discard any number of cards from your hand. Deal that much damage to a unit or base.',
    // Epic Action: free deploy at 7+ resources.
    epicDeploy: {
      label: 'Epic Action: deploy Darth Vader for free (7+ resources)',
      usable: function (g, side) { return g.player(side).resources.length >= 7; }
    },
    // Undeployed action ability.
    leaderAction: {
      label: 'Vader: exhaust + discard a card → 1 damage',
      usable: function (g, side) {
        var p = g.player(side);
        return !p.leader.deployed && !p.leader.exhausted && p.hand.length > 0;
      },
      use: function (g, side) {
        var p = g.player(side);
        g.prompt(side, {
          text: 'Discard a card from your hand (cost of Vader\'s ability)',
          optional: false, hint: 'hand-discard',
          options: p.hand.map(function (c) { return { id: c.uid, label: g.cardLabel(c) }; })
        }, function (picked) {
          var c = p.hand.filter(function (x) { return x.uid === picked[0]; })[0];
          p.leader.exhausted = true;
          g.discardFromHand(side, c);
          var targets = g.targets(side, { enemyUnits: true, friendlyUnits: true, bases: true });
          g.prompt(side, {
            text: 'Deal 1 damage to a unit or base', optional: false, hint: 'damage',
            options: g.asOptions(targets)
          }, function (picked2) {
            g.damage(picked2[0], 1, p.leader);
          });
        });
      }
    },
    // Deployed unit ability.
    onAttack: function (g, card) {
      var p = g.player(card.controller);
      if (!p.hand.length) return;
      g.prompt(card.controller, {
        text: 'Discard any number of cards → that much damage to a unit or base',
        optional: true, multi: true, hint: 'vader-discard',
        options: p.hand.map(function (c) { return { id: c.uid, label: g.cardLabel(c) }; })
      }, function (picked) {
        if (!picked.length) return;
        picked.forEach(function (uid) {
          var c = p.hand.filter(function (x) { return x.uid === uid; })[0];
          if (c) g.discardFromHand(card.controller, c);
        });
        var n = picked.length;
        var targets = g.targets(card.controller, { enemyUnits: true, friendlyUnits: true, bases: true });
        g.prompt(card.controller, {
          text: 'Deal ' + n + ' damage to a unit or base', optional: false, hint: 'damage',
          options: g.asOptions(targets)
        }, function (picked2) {
          g.damage(picked2[0], n, card);
        });
      });
    }
  };

  var BASE = {
    id: 'partisan-hideout', name: 'Partisan Hideout', hp: 27, aspects: [CUN],
    text: 'Epic Action: Play a card from your hand, ignoring 1 of its aspect penalties.',
    epicAction: {
      label: 'Epic Action: play a card ignoring 1 aspect penalty',
      // Always offerable while unused - the discount is only worth anything on a
      // card with an uncovered aspect, and the option labels show the real cost.
      usable: function (g, side) { return g.player(side).hand.length > 0; },
      use: function (g, side) {
        var p = g.player(side);
        var options = [];
        p.hand.forEach(function (c) {
          var discount = Math.min(2, g.aspectPenalty(side, c));
          if (!g.canAfford(side, c, discount)) return;
          var full = g.costOf(side, c, 0), net = g.costOf(side, c, discount);
          options.push({
            id: c.uid,
            label: c.def.name + ' — pay ' + net + (net < full ? ' (was ' + full + ')' : ' (no penalty to ignore)')
          });
        });
        if (!options.length) { g.log('No card in hand can be played this way.'); return; }
        g.prompt(side, {
          text: 'Epic Action: play a card, ignoring 1 of its aspect penalties',
          optional: true, hint: 'base-epic', options: options
        }, function (picked) {
          if (!picked.length) { g.cancelAction(); return; }   // backing out is free
          var card = p.hand.filter(function (x) { return x.uid === picked[0]; })[0];
          if (!card) { g.cancelAction(); return; }
          p.epicUsed.base = true;
          g.log(g.says(side, 'use') + ' the Partisan Hideout Epic Action.');
          g.playCard(side, card, { discount: Math.min(2, g.aspectPenalty(side, card)) });
        });
      }
    }
  };

  // --------------------------------------------------------------- the deck
  // qty is expanded by the engine when the deck is built.
  var DECK = [
    // --- 1 drops
    { qty: 1, id: 'savareen-survivor', name: 'Savareen Survivor', type: 'unit', cost: 1,
      power: 2, hp: 1, arena: 'ground', aspects: [AGG], keywords: { hidden: true },
      text: 'Hidden' },

    { qty: 1, id: 'storm-raider', name: 'Storm Raider', type: 'unit', cost: 1,
      power: 2, hp: 2, arena: 'ground', aspects: [AGG, VIL], keywords: { raid: 1 },
      text: 'Raid 1' },

    { qty: 1, id: 'nihil-stormsower', name: 'Nihil Stormsower', type: 'unit', cost: 1,
      power: 2, hp: 2, arena: 'ground', aspects: [CUN, VIL], keywords: { hidden: true },
      text: 'Hidden' },

    { qty: 1, id: 'rookie-rocket-jumper', name: 'Rookie Rocket-Jumper', type: 'unit', cost: 1,
      power: 2, hp: 1, arena: 'ground', aspects: [CUN],
      text: 'When Played: You may pay 1 to give this unit a Shield token.',
      onPlay: function (g, card) {
        var p = g.player(card.controller);
        if (!g.canPay(p, 1)) return;
        g.prompt(card.controller, {
          text: 'Pay 1 to give Rookie Rocket-Jumper a Shield?', optional: true, hint: 'may-pay',
          options: [{ id: 'yes', label: 'Pay 1 for a Shield' }]
        }, function (picked) {
          if (!picked.length) return;
          g.pay(p, 1);
          g.addShield(card);
        });
      } },

    { qty: 1, id: 'salacious-crumb', name: 'Salacious Crumb', type: 'unit', cost: 1,
      power: 0, hp: 2, arena: 'ground', aspects: [CUN, VIL], keywords: { raid: 2 },
      text: 'Raid 2. (Enters ready if you control Jabba — no Jabba in this deck.)' },

    // --- 2 drops
    { qty: 1, id: 'weequay-pirate', name: 'Weequay Pirate', type: 'unit', cost: 2,
      power: 2, hp: 3, arena: 'ground', aspects: [CUN], keywords: { saboteur: true },
      text: 'Saboteur. When Played: If no resources were paid, give this unit an Experience token.',
      onPlay: function (g, card) {
        if (card.resourcesPaid === 0) {
          g.addExperience(card);
          g.log('Weequay Pirate was played for free — Experience token added.');
        }
      } },

    { qty: 1, id: 'ohnaka-gang-starhopper', name: 'Ohnaka Gang Starhopper', type: 'unit', cost: 2,
      power: 2, hp: 2, arena: 'space', aspects: [CUN], keywords: { saboteur: true },
      text: 'Saboteur' },

    { qty: 1, id: 'cavern-angels-xwing', name: 'Cavern Angels X-Wing', type: 'unit', cost: 2,
      power: 2, hp: 1, arena: 'space', aspects: [AGG],
      text: 'When Defeated: Deal 2 damage to a base.',
      onDefeated: damageTarget(2, { bases: true }, 'Deal 2 damage to a base', false) },

    // --- 3 drops
    { qty: 1, id: 'arvel-skeen', name: 'Arvel Skeen', type: 'unit', cost: 3,
      power: 4, hp: 3, arena: 'ground', aspects: [AGG],
      text: 'When Played / On Attack: You may defeat a Credit token to deal 1 damage to a unit or base.',
      onPlay: spendCreditForDamage, onAttack: spendCreditForDamage },

    { qty: 1, id: 'callous-bounty-hunter', name: 'Callous Bounty Hunter', type: 'unit', cost: 3,
      power: 3, hp: 4, arena: 'ground', aspects: [VIL], keywords: { saboteur: true },
      text: 'Saboteur' },

    { qty: 1, id: 'kage-elite', name: 'Kage Elite', type: 'unit', cost: 3,
      power: 2, hp: 3, arena: 'ground', aspects: [CUN], keywords: { raid: 2, saboteur: true },
      text: 'Raid 2. Saboteur' },

    { qty: 1, id: 'sebulbas-podracer', name: "Sebulba's Podracer", type: 'unit', cost: 3,
      power: 3, hp: 3, arena: 'ground', aspects: [AGG, VIL],
      text: 'When you discard a card from your deck: You may ready this unit. (Once per round.)',
      onOwnerDeckDiscard: function (g, card) {
        if (card.usedThisRound || !card.exhausted) return;
        g.prompt(card.controller, {
          text: 'Ready ' + card.def.name + '?', optional: true, hint: 'ready-self',
          options: [{ id: 'yes', label: 'Ready it' }]
        }, function (picked) {
          if (!picked.length) return;
          card.exhausted = false;
          card.usedThisRound = true;
          g.log(card.def.name + ' readies.');
        });
      } },

    { qty: 1, id: 'champions-kt9-podracer', name: "Champion's KT9 Podracer", type: 'unit', cost: 3,
      power: 2, hp: 3, arena: 'ground', aspects: [CUN],
      text: 'When Played: Create a Credit token.',
      onPlay: function (g, card) {
        g.player(card.controller).credits += 1;
        g.log(g.says(card.controller, 'create') + ' a Credit token.');
      } },

    { qty: 1, id: 'prototype-tie-advanced', name: 'Prototype TIE Advanced', type: 'unit', cost: 3,
      power: 4, hp: 3, arena: 'space', aspects: [AGG, VIL], text: '—' },

    { qty: 1, id: 'vult-skerriss-defender', name: "Vult Skerris's Defender", type: 'unit', cost: 3,
      power: 3, hp: 3, arena: 'space', aspects: [AGG, CUN, VIL],
      text: 'When Played: If you discarded a card this phase, give this unit a Shield token. ' +
            'On Attack: Deal 1 damage to a space unit and exhaust it.',
      onPlay: function (g, card) {
        if (g.player(card.controller).discardedThisPhase > 0) {
          g.addShield(card);
          g.log("Vult Skerris's Defender gains a Shield.");
        }
      },
      onAttack: function (g, card) {
        var targets = g.targets(card.controller, { enemyUnits: true, friendlyUnits: true, arena: 'space' })
          .filter(function (t) { return t.uid !== card.uid; });
        if (!targets.length) return;
        g.prompt(card.controller, {
          text: 'Deal 1 damage to a space unit and exhaust it', optional: true, hint: 'damage',
          options: g.asOptions(targets)
        }, function (picked) {
          if (!picked.length) return;
          var t = g.findUnit(picked[0]);
          if (!t) return;
          g.damage(picked[0], 1, card);
          if (t.zone === 'play') { t.exhausted = true; g.log(t.def.name + ' is exhausted.'); }
        });
      } },

    // --- 4 drops
    { qty: 1, id: 'cutthroat-podracer', name: 'Cutthroat Podracer', type: 'unit', cost: 4,
      power: 4, hp: 4, arena: 'ground', aspects: [CUN, VIL],
      text: 'When Played: You may deal 2 damage to an exhausted ground unit.',
      onPlay: function (g, card) {
        var targets = g.targets(card.controller, { enemyUnits: true, friendlyUnits: true, arena: 'ground' })
          .filter(function (t) { return t.exhausted && t.uid !== card.uid; });
        if (!targets.length) return;
        g.prompt(card.controller, {
          text: 'Deal 2 damage to an exhausted ground unit', optional: true, hint: 'damage',
          options: g.asOptions(targets)
        }, function (picked) {
          if (picked.length) g.damage(picked[0], 2, card);
        });
      } },

    { qty: 1, id: 'qui-gon-jinn', name: 'Qui-Gon Jinn', type: 'unit', cost: 4,
      power: 3, hp: 5, arena: 'ground', aspects: [CUN], keywords: { sentinel: true },
      text: 'Sentinel. When Played / On Attack: Look at the top 3 cards of your deck. You may discard 1.',
      onPlay: lookTop3Discard1, onAttack: lookTop3Discard1 },

    { qty: 1, id: 'urrrk', name: "Urrr'k", type: 'unit', cost: 4,
      power: 2, hp: 4, arena: 'ground', aspects: [AGG, CUN], keywords: { hidden: true, raid: 4 },
      text: 'Hidden. Raid 4' },

    { qty: 2, id: 'overcharged-transport', name: 'Overcharged Transport', type: 'unit', cost: 4,
      power: 4, hp: 3, arena: 'space', aspects: [AGG],
      text: 'When Played / When Defeated: You may defeat an upgrade on a space unit.',
      onPlay: defeatUpgradeOnSpaceUnit, onDefeated: defeatUpgradeOnSpaceUnit },

    // --- 5 drops
    { qty: 2, id: 'dogged-pursuers', name: 'Dogged Pursuers', type: 'unit', cost: 5,
      power: 5, hp: 5, arena: 'ground', aspects: [AGG],
      text: 'When Played: You may pay 1 to deal 2 damage to a ground unit.',
      onPlay: mayPayThenDamage(1, 2, { enemyUnits: true, friendlyUnits: true, arena: 'ground' },
        'Pay 1 to deal 2 damage to a ground unit?') },

    { qty: 1, id: 'night-wind-assailants', name: 'Night Wind Assailants', type: 'unit', cost: 5,
      power: 5, hp: 5, arena: 'ground', aspects: [VIL], keywords: { sentinel: true },
      text: 'Sentinel' },

    // --- 6 drop
    { qty: 1, id: 'milodon-rider', name: 'Milodon Rider', type: 'unit', cost: 6,
      power: 5, hp: 6, arena: 'ground', aspects: [CUN], keywords: { ambush: true },
      text: 'Ambush. When Played: You may return another friendly non-leader unit to your hand.',
      onPlay: function (g, card) {
        var friends = g.player(card.controller).units.filter(function (u) { return u.uid !== card.uid; });
        if (!friends.length) return;
        g.prompt(card.controller, {
          text: 'Return another friendly unit to your hand?', optional: true, hint: 'bounce-friendly',
          options: g.asOptions(friends)
        }, function (picked) {
          if (picked.length) g.returnToHand(picked[0]);
        });
      } },

    // --- Events
    { qty: 1, id: 'commence-the-festivities', name: 'Commence the Festivities', type: 'event', cost: 1,
      aspects: [AGG],
      text: 'Attack with a unit. It gains Saboteur for this attack. If you control fewer resources than ' +
            'an opponent, it gets +2/+0 for this attack.',
      onPlay: function (g, card, side) {
        var ready = g.player(side).units.filter(function (u) { return !u.exhausted; });
        if (!ready.length) { g.log('No ready unit to attack with.'); return; }
        g.prompt(side, {
          text: 'Attack with a unit (it gains Saboteur)', optional: true, hint: 'attacker',
          options: g.asOptions(ready)
        }, function (picked) {
          if (!picked.length) return;
          var unit = g.findUnit(picked[0]);
          if (!unit) return;
          var mods = { saboteur: true };
          if (g.player(side).resources.length < g.player(g.other(side)).resources.length) mods.power = 2;
          g.beginAttack(unit, mods);
        });
      } },

    { qty: 1, id: 'daring-delve', name: 'Daring Delve', type: 'event', cost: 1, aspects: [AGG],
      text: 'Discard 2 cards from your deck. You may return an Aggression card discarded this way to your hand.',
      onPlay: function (g, card, side) {
        var p = g.player(side);
        var discarded = [];
        for (var i = 0; i < 2; i++) {
          if (!p.deck.length) break;
          var c = p.deck[0];
          g.discardFromDeck(side, c);
          discarded.push(c);
        }
        var agg = discarded.filter(function (c) { return (c.def.aspects || []).indexOf(AGG) >= 0; });
        if (!agg.length) return;
        g.prompt(side, {
          text: 'Return an Aggression card to your hand?', optional: true, hint: 'recur',
          options: agg.map(function (c) { return { id: c.uid, label: g.cardLabel(c) }; })
        }, function (picked) {
          if (picked.length) g.returnFromDiscardToHand(side, picked[0]);
        });
      } },

    { qty: 1, id: 'improvise', name: 'Improvise', type: 'event', cost: 1, aspects: [CUN],
      text: 'Look at the top card of your deck. You may play it for 1 less. If you do not, you may discard it.',
      onPlay: function (g, card, side) {
        var p = g.player(side);
        if (!p.deck.length) return;
        var top = p.deck[0];
        var opts = [];
        if (g.canAfford(side, top, -1)) opts.push({ id: 'play', label: 'Play ' + g.cardLabel(top) + ' for 1 less' });
        opts.push({ id: 'discard', label: 'Discard ' + g.cardLabel(top) });
        g.prompt(side, {
          text: 'Top of deck: ' + g.cardLabel(top), optional: true, hint: 'improvise', options: opts
        }, function (picked) {
          if (!picked.length) return;
          if (picked[0] === 'play') {
            p.deck.shift();
            p.hand.push(top);
            g.playCard(side, top, { discount: 1, free: false });
          } else {
            g.discardFromDeck(side, top);
          }
        });
      } },

    { qty: 1, id: 'you-hold-this', name: 'You Hold This', type: 'event', cost: 1, aspects: [AGG, CUN],
      text: 'An opponent takes control of a friendly non-leader unit. Deal 4 damage to another unit in that arena.',
      onPlay: function (g, card, side) {
        var friends = g.player(side).units;
        if (!friends.length) { g.log('No unit to hand over.'); return; }
        g.prompt(side, {
          text: 'Give the opponent control of one of your units', optional: false, hint: 'give-away',
          options: g.asOptions(friends)
        }, function (picked) {
          var unit = g.findUnit(picked[0]);
          if (!unit) return;
          var arena = unit.def.arena;
          g.changeControl(unit, g.other(side));
          var targets = g.targets(side, { enemyUnits: true, friendlyUnits: true, arena: arena })
            .filter(function (t) { return t.uid !== unit.uid; });
          if (!targets.length) return;
          g.prompt(side, {
            text: 'Deal 4 damage to another unit in the ' + arena + ' arena', optional: false, hint: 'damage',
            options: g.asOptions(targets)
          }, function (picked2) { g.damage(picked2[0], 4, card); });
        });
      } },

    { qty: 1, id: 'collateral-damage', name: 'Collateral Damage', type: 'event', cost: 3, aspects: [AGG],
      text: 'Deal 2 damage to a unit. Then deal 2 damage to a base or another unit in that arena.',
      onPlay: function (g, card, side) {
        var targets = g.targets(side, { enemyUnits: true, friendlyUnits: true });
        if (!targets.length) { g.log('No unit to damage.'); return; }
        g.prompt(side, {
          text: 'Deal 2 damage to a unit', optional: false, hint: 'damage', options: g.asOptions(targets)
        }, function (picked) {
          var first = g.findUnit(picked[0]);
          var arena = first ? first.def.arena : null;
          g.damage(picked[0], 2, card);
          var second = g.targets(side, { enemyUnits: true, friendlyUnits: true, arena: arena, bases: true })
            .filter(function (t) { return t.uid !== picked[0]; });
          if (!second.length) return;
          g.prompt(side, {
            text: 'Deal 2 damage to a base or another ' + arena + ' unit', optional: false, hint: 'damage',
            options: g.asOptions(second)
          }, function (picked2) { g.damage(picked2[0], 2, card); });
        });
      } },

    // --- Upgrade
    { qty: 1, id: 'salvaged-blaster', name: 'Salvaged Blaster', type: 'upgrade', cost: 2, aspects: [AGG],
      power: 2, hpBonus: 0,
      text: 'Attach to a non-Vehicle unit: +2/+0. Action: If this was discarded from your hand or deck ' +
            'this phase, you may play it from your discard pile (paying its cost).',
      playableFromDiscard: true,
      onPlay: function (g, card, side) {
        var targets = g.player(side).units.filter(function (u) {
          return (u.def.traits || []).indexOf('Vehicle') < 0;
        });
        if (!targets.length) { g.log('No legal unit to attach Salvaged Blaster to.'); return; }
        g.prompt(side, {
          text: 'Attach Salvaged Blaster (+2/+0)', optional: false, hint: 'attach',
          options: g.asOptions(targets)
        }, function (picked) {
          var unit = g.findUnit(picked[0]);
          if (unit) {
            unit.upgrades.push({ name: 'Salvaged Blaster', power: 2, hp: 0 });
            g.log('Salvaged Blaster attached to ' + unit.def.name + '.');
          }
        });
      } }
  ];

  global.SWU_CARDS = {
    ASPECTS: { AGG: AGG, VIL: VIL, CUN: CUN, CMD: CMD, VIG: VIG, HER: HER },
    LEADER: LEADER, BASE: BASE, DECK: DECK,
    DECK_NAME: 'Vader Sealed — A Lawless Time'
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
