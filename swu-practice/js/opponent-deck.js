/* Opponent deck: a generic "sparring" sealed deck.
 *
 * These are NOT real Star Wars Unlimited cards. They are plain practice bodies
 * with a realistic sealed curve, aspect spread and keyword mix, so that you can
 * drill your own deck's sequencing against something that behaves like an
 * average sealed opponent.
 *
 * To practise against a real list instead, replace DECK below with the same
 * shape of definitions (see js/cards.js for the format and available hooks).
 */
(function (global) {
  'use strict';
  var A = global.SWU_CARDS.ASPECTS;

  var LEADER = {
    id: 'sparring-commander', name: 'Sparring Commander', subtitle: 'Practice Partner',
    set: 'GENERIC', cost: 6, power: 4, hp: 7, arena: 'ground',
    aspects: [A.CMD, A.VIG], traits: ['Generic'],
    text: 'Action [exhaust]: Give a friendly unit +1/+0 for this phase.',
    leaderAction: {
      label: 'Commander: exhaust → a friendly unit gets +1/+0',
      usable: function (g, side) {
        var p = g.player(side);
        return !p.leader.deployed && !p.leader.exhausted && p.units.length > 0;
      },
      use: function (g, side) {
        var p = g.player(side);
        p.leader.exhausted = true;
        var unit = p.units[0];
        unit.tempPower = (unit.tempPower || 0) + 1;
        g.log('Sparring Commander gives ' + unit.def.name + ' +1/+0.');
      }
    }
  };

  var BASE = { id: 'sparring-outpost', name: 'Sparring Outpost', hp: 27, aspects: [A.CMD], text: '—' };

  var DECK = [
    { qty: 2, id: 'g-scout', name: 'Outpost Scout', type: 'unit', cost: 1, power: 2, hp: 1,
      arena: 'ground', aspects: [A.CMD], text: '—' },
    { qty: 2, id: 'g-picket', name: 'Picket Flyer', type: 'unit', cost: 1, power: 1, hp: 2,
      arena: 'space', aspects: [A.VIG], text: '—' },
    { qty: 1, id: 'g-guard', name: 'Gate Guard', type: 'unit', cost: 2, power: 2, hp: 3,
      arena: 'ground', aspects: [A.VIG], keywords: { sentinel: true }, text: 'Sentinel' },
    { qty: 2, id: 'g-raider', name: 'Border Raider', type: 'unit', cost: 2, power: 3, hp: 2,
      arena: 'ground', aspects: [A.CMD], keywords: { raid: 1 }, text: 'Raid 1' },
    { qty: 2, id: 'g-interceptor', name: 'Patrol Interceptor', type: 'unit', cost: 2, power: 2, hp: 2,
      arena: 'space', aspects: [A.CMD], text: '—' },
    { qty: 2, id: 'g-marksman', name: 'Ridge Marksman', type: 'unit', cost: 3, power: 3, hp: 3,
      arena: 'ground', aspects: [A.VIG],
      text: 'When Played: Deal 1 damage to a unit.',
      onPlay: function (g, card) {
        var targets = g.targets(card.controller, { enemyUnits: true });
        if (!targets.length) return;
        g.prompt(card.controller, {
          text: 'Deal 1 damage to a unit', optional: true, hint: 'damage', options: g.asOptions(targets)
        }, function (picked) { if (picked.length) g.damage(picked[0], 1, card); });
      } },
    { qty: 2, id: 'g-gunship', name: 'Escort Gunship', type: 'unit', cost: 3, power: 3, hp: 4,
      arena: 'space', aspects: [A.CMD], text: '—' },
    { qty: 1, id: 'g-bulwark', name: 'Shield Bulwark', type: 'unit', cost: 3, power: 2, hp: 4,
      arena: 'ground', aspects: [A.VIG], keywords: { sentinel: true }, text: 'Sentinel' },
    { qty: 2, id: 'g-veteran', name: 'Veteran Trooper', type: 'unit', cost: 4, power: 4, hp: 4,
      arena: 'ground', aspects: [A.CMD], text: '—' },
    { qty: 1, id: 'g-frigate', name: 'Blockade Frigate', type: 'unit', cost: 4, power: 3, hp: 5,
      arena: 'space', aspects: [A.VIG], keywords: { sentinel: true }, text: 'Sentinel' },
    { qty: 1, id: 'g-champion', name: 'Garrison Champion', type: 'unit', cost: 5, power: 5, hp: 5,
      arena: 'ground', aspects: [A.CMD], text: '—' },
    { qty: 1, id: 'g-walker', name: 'Siege Walker', type: 'unit', cost: 6, power: 5, hp: 6,
      arena: 'ground', aspects: [A.CMD], traits: ['Vehicle'], keywords: { raid: 2 }, text: 'Raid 2' },
    { qty: 1, id: 'g-cruiser', name: 'Line Cruiser', type: 'unit', cost: 6, power: 4, hp: 6,
      arena: 'space', aspects: [A.VIG], traits: ['Vehicle'], text: '—' },
    { qty: 2, id: 'g-volley', name: 'Covering Volley', type: 'event', cost: 2, aspects: [A.VIG],
      text: 'Deal 3 damage to a unit.',
      onPlay: function (g, card, side) {
        var targets = g.targets(side, { enemyUnits: true });
        if (!targets.length) { g.log('No unit to damage.'); return; }
        g.prompt(side, {
          text: 'Deal 3 damage to a unit', optional: false, hint: 'damage', options: g.asOptions(targets)
        }, function (picked) { g.damage(picked[0], 3, card); });
      } },
    { qty: 1, id: 'g-rally', name: 'Rally the Line', type: 'event', cost: 2, aspects: [A.CMD],
      text: 'Draw 2 cards.',
      onPlay: function (g, card, side) { g.draw(side, 2); } },
    { qty: 1, id: 'g-hand', name: 'Garrison Hand', type: 'unit', cost: 2, power: 2, hp: 2,
      arena: 'ground', aspects: [A.VIG], text: '—' },
    { qty: 1, id: 'g-skiff', name: 'Transport Skiff', type: 'unit', cost: 3, power: 3, hp: 2,
      arena: 'space', aspects: [A.CMD], traits: ['Vehicle'], text: '—' },
    { qty: 1, id: 'g-sentry', name: 'Perimeter Sentry', type: 'unit', cost: 4, power: 4, hp: 3,
      arena: 'ground', aspects: [A.VIG], text: '—' },
    { qty: 2, id: 'g-porter', name: 'Supply Porter', type: 'unit', cost: 2, power: 1, hp: 3,
      arena: 'ground', aspects: [A.CMD], text: '—' },
    { qty: 1, id: 'g-runner', name: 'Courier Shuttle', type: 'unit', cost: 3, power: 2, hp: 2,
      arena: 'space', aspects: [A.VIG], text: '—' },
    { qty: 1, id: 'g-armory', name: 'Armory Runner', type: 'unit', cost: 4, power: 3, hp: 4,
      arena: 'ground', aspects: [A.CMD], text: '—' }
  ];

  global.SWU_OPPONENT = {
    LEADER: LEADER, BASE: BASE, DECK: DECK,
    DECK_NAME: 'Generic Sparring Sealed (Command / Vigilance)'
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
