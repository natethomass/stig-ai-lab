/* Browser UI: renders the board, turns clicks into engine actions, and steps
 * the AI on a timer so its turns are readable.
 */
(function (global) {
  'use strict';

  var g = null;
  var selectedPrompt = [];      // for multi-select prompts
  var aiTimer = null;

  var $ = function (id) { return document.getElementById(id); };

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  // ------------------------------------------------------------ card render
  function keywordLine(def) {
    var k = def.keywords || {}, out = [];
    if (k.sentinel) out.push('Sentinel');
    if (k.saboteur) out.push('Saboteur');
    if (k.ambush) out.push('Ambush');
    if (k.hidden) out.push('Hidden');
    if (k.raid) out.push('Raid ' + k.raid);
    return out.join(' · ');
  }

  function cardNode(card, opts) {
    opts = opts || {};
    var def = card.def;
    var node = el('div', 'card');
    node.dataset.uid = card.uid;
    node.dataset.aspect = (def.aspects && def.aspects[0]) || 'None';
    node.title = def.name + (def.text ? '\n\n' + def.text : '');

    var artUrl = global.SWU_ART ? global.SWU_ART.urlFor(def) : null;
    if (artUrl) {
      var img = document.createElement('img');
      img.className = 'art';
      img.alt = '';
      img.loading = 'lazy';
      img.src = artUrl;
      img.onerror = function () {
        global.SWU_ART.markFailed(artUrl);
        node.classList.remove('has-art');
        if (img.parentNode) img.parentNode.removeChild(img);
      };
      node.classList.add('has-art');
      node.appendChild(img);
    }

    var cost = el('div', 'cost', String(def.cost != null ? def.cost : ''));
    if (opts.showCost !== false && def.cost != null) node.appendChild(cost);

    var aspects = el('div', 'aspects');
    (def.aspects || []).forEach(function (a) { aspects.appendChild(el('span', 'dot ' + a)); });
    node.appendChild(aspects);

    node.appendChild(el('div', 'nm', def.name));

    var kw = keywordLine(def);
    if (kw) node.appendChild(el('div', 'kw', kw));

    if (card.upgrades && card.upgrades.length) {
      var toks = el('div', 'toks');
      card.upgrades.forEach(function (u) {
        toks.appendChild(el('span', 'tok ' + (u.shield ? 'shield' : u.experience ? 'exp' : 'upg'), u.name));
      });
      node.appendChild(toks);
    }

    if (def.type === 'unit' || card.isLeader) {
      var p = card.power ? card.power() : def.power;
      var hp = card.hp ? card.hp() : def.hp;
      var remaining = card.remainingHp ? card.remainingHp() : hp;
      node.appendChild(el('div', 'stat', p + ' power · ' +
        (remaining !== hp ? remaining + ' of ' + hp + ' HP' : hp + ' HP') +
        ' · ' + (def.arena === 'space' ? 'Space' : 'Ground')));
      if (card.damage > 0) node.classList.add('damaged');
    } else {
      node.appendChild(el('div', 'stat', def.type === 'event' ? 'Event' : 'Upgrade'));
    }

    if (card.exhausted) node.classList.add('exhausted');
    return node;
  }

  // ----------------------------------------------------------------- render
  function render() {
    if (!g) return;
    var you = g.player('you'), ai = g.player('ai');
    var acts = g.legalActions('you');
    var pending = g.pending && g.pending.side === 'you' ? g.pending : null;
    var promptIds = pending ? pending.options.map(function (o) { return o.id; }) : [];

    $('ai-deckname').textContent = ai.deckName;
    $('ai-hand').textContent = 'Hand ' + ai.hand.length;
    $('ai-deck').textContent = 'Deck ' + ai.deck.length;
    $('ai-discard').textContent = 'Discard ' + ai.discard.length;
    $('ai-res').textContent = 'Resources ' + g.readyResources(ai) + '/' + ai.resources.length;
    $('you-deck').textContent = 'Deck ' + you.deck.length;
    $('you-discard').textContent = 'Discard ' + you.discard.length;
    $('you-res').textContent = 'Resources ' + g.readyResources(you) + '/' + you.resources.length;
    $('you-credits').textContent = 'Credits ' + you.credits;

    renderBase($('ai-base'), ai, promptIds, pending);
    renderBase($('you-base'), you, promptIds, pending);
    renderLeader($('ai-leader'), ai);
    renderLeader($('you-leader'), you);

    ['space', 'ground'].forEach(function (arena) {
      fillRow($('ai-' + arena), ai.units.filter(function (u) { return u.def.arena === arena; }),
        false, acts, promptIds, pending);
      fillRow($('you-' + arena), you.units.filter(function (u) { return u.def.arena === arena; }),
        true, acts, promptIds, pending);
    });

    // Hand
    var hand = $('you-hand');
    hand.innerHTML = '';
    you.hand.forEach(function (c) {
      var playAct = acts.filter(function (a) { return a.kind === 'play' && a.cardUid === c.uid; })[0];
      var node = cardNode(c);
      var cost = g.costOf('you', c, 0);
      if (cost !== c.def.cost) node.querySelector('.cost').textContent = String(cost);
      if (pending && promptIds.indexOf(c.uid) >= 0) {
        node.classList.add('targetable');
        node.onclick = function () { pickOption(c.uid); };
      } else if (playAct && !pending) {
        node.classList.add('playable');
        node.onclick = function () { act(playAct); };
      } else {
        node.classList.add('unplayable');
      }
      if (selectedPrompt.indexOf(c.uid) >= 0) node.classList.add('selected');
      hand.appendChild(node);
    });

    var meLabel = $('me-label');
    if (meLabel) meLabel.textContent = g.player('you').name;
    renderStatus();
    renderWinOverlay();
    renderPrompt(pending);
    renderActions(acts, pending);
    syncDockHeight();
    renderLog();
  }

  function renderBase(box, p, promptIds, pending) {
    box.innerHTML = '';
    var pct = Math.max(0, p.base.remainingHp()) / p.base.def.hp * 100;
    box.appendChild(el('div', 'bname', p.base.def.name));
    box.appendChild(el('div', 'meta', Math.max(0, p.base.remainingHp()) + ' / ' + p.base.def.hp + ' HP' +
      (p.base.def.text && p.base.def.text !== '—' ? ' · Epic Action available' : '')));
    var bar = el('div', 'hpbar' + (pct < 35 ? ' low' : ''));
    var fill = el('i'); fill.style.width = pct + '%';
    bar.appendChild(fill);
    box.appendChild(bar);
    if (pending && promptIds.indexOf(p.base.uid) >= 0) {
      box.style.cursor = 'pointer';
      box.style.outline = '2px solid #6cd0ff';
      box.onclick = function () { pickOption(p.base.uid); };
    } else {
      box.style.outline = 'none';
      box.style.cursor = 'default';
      box.onclick = null;
    }
  }

  function renderLeader(box, p) {
    box.innerHTML = '';
    var l = p.leader;
    box.appendChild(el('div', 'bname', l.def.name + (l.def.subtitle ? ' — ' + l.def.subtitle : '')));
    var state = l.deployed ? 'Deployed as a unit' : (l.exhausted ? 'Exhausted' : 'Ready');
    box.appendChild(el('div', 'meta', l.def.power + '/' + l.def.hp + ' · ' + state));
    if (l.def.text) {
      var t = el('div', 'meta', l.def.text);
      t.style.marginTop = '5px';
      t.style.fontSize = '10.5px';
      t.style.maxHeight = '46px';
      t.style.overflow = 'hidden';
      t.title = l.def.text;
      box.appendChild(t);
    }
  }

  function fillRow(row, units, mine, acts, promptIds, pending) {
    row.innerHTML = '';
    units.forEach(function (u) {
      var node = cardNode(u);
      if (pending && promptIds.indexOf(u.uid) >= 0) {
        node.classList.add('targetable');
        node.onclick = function () { pickOption(u.uid); };
      } else if (mine && !pending) {
        var atk = acts.filter(function (a) { return a.kind === 'attack' && a.cardUid === u.uid; })[0];
        if (atk) {
          node.classList.add('attacker');
          node.onclick = function () { act(atk); };
        }
      }
      if (selectedPrompt.indexOf(u.uid) >= 0) node.classList.add('selected');
      row.appendChild(node);
    });
  }

  function renderStatus() {
    var box = $('status');
    box.className = 'status';
    box.innerHTML = '';
    if (g.winner) {
      box.classList.add(g.winner === 'you' ? 'win' : g.winner === 'ai' ? 'lose' : '');
      box.appendChild(el('div', 'round',
        g.winner === 'you' ? 'You win!' : g.winner === 'ai' ? 'Opponent wins' : 'Draw'));
      box.appendChild(el('div', 'turn', 'Round ' + g.round + ' · press New game to play again'));
      return;
    }
    box.appendChild(el('div', 'round', 'Round ' + g.round + ' · ' +
      (g.phase === 'action' ? 'Action phase' : g.phase === 'regroup' ? 'Regroup phase' : 'Setup')));
    box.appendChild(el('div', 'turn', g.pending
      ? (g.pending.side === 'you' ? 'Waiting on your choice' : 'Opponent is choosing…')
      : (g.activePlayer === 'you' ? 'Your turn — take one action' : 'Opponent is thinking…')));
    var init = el('div', 'init');
    init.innerHTML = 'Initiative: <b>' + (g.initiative === 'you' ? g.player('you').name : 'Opponent') + '</b>' +
      (g.initiativeClaimedBy ? ' (claimed this round)' : ' (unclaimed this round)');
    box.appendChild(init);
  }

  function renderPrompt(pending) {
    var box = $('prompt');
    if (!pending) { box.hidden = true; box.innerHTML = ''; return; }
    box.hidden = false;
    box.innerHTML = '';
    box.appendChild(el('div', 'ptext', pending.text));
    var opts = el('div', 'opts');
    pending.options.forEach(function (o) {
      var b = el('button', 'btn' + (selectedPrompt.indexOf(o.id) >= 0 ? ' on' : ''), o.label);
      b.onclick = function () { pickOption(o.id); };
      opts.appendChild(b);
    });
    if (pending.multi) {
      var confirm = el('button', 'btn primary',
        'Confirm (' + selectedPrompt.length + ' selected)');
      confirm.onclick = function () { submitPrompt(selectedPrompt.slice()); };
      opts.appendChild(confirm);
    }
    if (pending.optional) {
      var skip = el('button', 'btn', pending.multi ? 'Discard nothing' : 'No thanks / skip');
      skip.onclick = function () { submitPrompt([]); };
      opts.appendChild(skip);
    }
    box.appendChild(opts);
  }

  function renderActions(acts, pending) {
    var box = $('actions');
    box.innerHTML = '';
    if (g.winner) return;
    box.appendChild(el('div', 'ahead', 'Actions'));
    if (pending) {
      box.appendChild(el('div', 'turn', 'Resolve the choice above first.'));
      return;
    }
    if (g.activePlayer !== 'you' || g.phase !== 'action') {
      box.appendChild(el('div', 'turn', 'Not your turn.'));
      return;
    }
    acts.filter(function (a) { return a.kind !== 'play' && a.kind !== 'attack'; })
      .forEach(function (a) {
        var b = el('button', 'btn' + (a.kind === 'epic-deploy' ? ' primary' : ''), a.label);
        b.onclick = function () { act(a); };
        box.appendChild(b);
      });
    var hint = el('div', 'turn hint',
      'Click a highlighted hand card to play it, or a green unit to attack.');
    box.appendChild(hint);
  }

  // The mobile hand docks above the action bar; measure it rather than guessing.
  function syncDockHeight() {
    var bar = $('actions');
    if (!bar || !global.document) return;
    var h = Math.ceil(bar.getBoundingClientRect().height);
    global.document.documentElement.style.setProperty('--dock-h', (h || 54) + 'px');
  }

  function renderLog() {
    var box = $('log');
    box.innerHTML = '';
    g.logLines.slice(-90).reverse().forEach(function (line) {
      var d = el('div', /^You\b/.test(line.text) ? 'you' : '');
      d.appendChild(el('span', 'r', 'R' + line.round));
      d.appendChild(document.createTextNode(line.text));
      box.appendChild(d);
    });
  }

  // ------------------------------------------------------------ interaction
  function pickOption(id) {
    var pending = g.pending;
    if (!pending || pending.side !== 'you') return;
    if (pending.multi) {
      var i = selectedPrompt.indexOf(id);
      if (i >= 0) selectedPrompt.splice(i, 1); else selectedPrompt.push(id);
      render();
      return;
    }
    submitPrompt([id]);
  }

  function submitPrompt(ids) {
    selectedPrompt = [];
    g.resolvePending(ids);
    render();
    scheduleAi();
  }

  function act(action) {
    if (!g || g.winner || g.pending) return;
    g.doAction('you', action);
    render();
    scheduleAi();
  }

  // Step the AI (and any automatic phase changes) on a timer.
  function scheduleAi() {
    clearTimeout(aiTimer);
    if (!g || g.winner) { render(); return; }
    var needsAi = (g.pending && g.pending.side === 'ai') ||
                  (!g.pending && g.phase === 'action' && g.activePlayer === 'ai');
    if (!needsAi) { render(); return; }
    aiTimer = setTimeout(function () {
      global.SWU_AI.takeAction(g, 'ai');
      render();
      scheduleAi();
    }, 650);
  }

  // ------------------------------------------------------------------ setup
  function newGame() {
    clearTimeout(aiTimer);
    selectedPrompt = [];
    if ($('win-overlay')) $('win-overlay').hidden = true;
    global.SWU_AI.setDifficulty($('difficulty').value);
    g = new global.SWU_ENGINE.Game({});
    global.swuGame = g;                       // handy for the console
    applyIdentity();
    g.start();
    render();
    scheduleAi();
  }

  function showDeck() {
    var body = $('modal-body');
    body.innerHTML = '';
    body.appendChild(el('h2', null, global.SWU_CARDS.DECK_NAME));
    var L = global.SWU_CARDS.LEADER, B = global.SWU_CARDS.BASE;
    body.appendChild(el('p', null, 'Leader: ' + L.name + ' — ' + L.subtitle + ' (' + L.set + ') · ' +
      L.cost + ' cost · ' + L.power + '/' + L.hp + ' · ' + L.aspects.join(' + ')));
    body.appendChild(el('p', null, 'Base: ' + B.name + ' · ' + B.hp + ' HP · ' + B.aspects.join(' + ')));

    var table = el('table');
    var thead = el('tr');
    ['Qty', 'Card', 'Cost', 'P/HP', 'Arena', 'Aspects', 'Text'].forEach(function (h) {
      thead.appendChild(el('th', null, h));
    });
    table.appendChild(thead);
    global.SWU_CARDS.DECK.slice().sort(function (a, b) {
      return (a.cost - b.cost) || a.name.localeCompare(b.name);
    }).forEach(function (d) {
      var tr = el('tr');
      [String(d.qty || 1), d.name, String(d.cost),
       d.type === 'unit' ? d.power + '/' + d.hp : (d.type === 'upgrade' ? '+' + d.power + '/+0' : '—'),
       d.type === 'unit' ? (d.arena === 'space' ? 'Space' : 'Ground') : '—',
       (d.aspects || []).join(', '), d.text || ''
      ].forEach(function (v) { tr.appendChild(el('td', null, v)); });
      table.appendChild(tr);
    });
    body.appendChild(table);
    $('modal').hidden = false;
  }

  // A starfield built from box-shadows: no image assets, deterministic per load.
  function buildStars() {
    var layer = $('stars');
    if (!layer) return;
    ['far', 'near'].forEach(function (depth, di) {
      var n = di === 0 ? 140 : 45;
      var shadows = [];
      for (var i = 0; i < n; i++) {
        var x = Math.round(Math.random() * 2000);
        var y = Math.round(Math.random() * 1400);
        var a = (di === 0 ? 0.25 : 0.5) + Math.random() * 0.35;
        shadows.push(x + 'px ' + y + 'px rgba(255,255,255,' + a.toFixed(2) + ')');
      }
      var d = el('i', 'star-layer ' + depth);
      d.style.boxShadow = shadows.join(', ');
      layer.appendChild(d);
    });
  }

  // Name goes on the header badge and straight into the running game.
  function applyIdentity() {
    var name = global.SWU_PREFS.name;
    var badge = $('pilot');
    if (badge) {
      badge.textContent = name === 'You' ? '' : name;
      badge.hidden = name === 'You';
    }
    if (g) g.players.you.name = name;
  }

  function renderWinOverlay() {
    var ov = $('win-overlay');
    if (!ov) return;
    if (!g || !g.winner) { ov.hidden = true; return; }
    ov.hidden = false;
    ov.innerHTML = '';
    var box = el('div', 'win-box ' + (g.winner === 'you' ? 'win' : g.winner === 'ai' ? 'lose' : 'draw'));
    box.appendChild(el('div', 'win-kicker', 'Round ' + g.round));
    box.appendChild(el('div', 'win-title',
      g.winner === 'you' ? 'Victory' : g.winner === 'ai' ? 'Defeat' : 'Draw'));
    box.appendChild(el('div', 'win-sub', g.winner === 'you'
      ? 'Sparring Outpost destroyed.'
      : g.winner === 'ai' ? 'Partisan Hideout destroyed.' : 'Both bases fell together.'));
    var again = el('button', 'btn primary', 'Play again');
    again.onclick = newGame;
    box.appendChild(again);
    var dismiss = el('button', 'btn', 'Review the board');
    dismiss.onclick = function () { ov.hidden = true; };
    box.appendChild(dismiss);
    ov.appendChild(box);
  }

  // ----------------------------------------------------------- settings modal
  function showSettings() {
    var cfg = global.SWU_ART.config;
    var body = $('modal-body');
    body.innerHTML = '';

    // --- profile -----------------------------------------------------------
    body.appendChild(el('h2', null, 'Settings'));
    body.appendChild(el('h3', 'sect', 'Your name'));
    var nameInput = document.createElement('input');
    nameInput.type = 'text';
    nameInput.className = 'artinput';
    nameInput.maxLength = 24;
    nameInput.placeholder = 'You';
    nameInput.value = global.SWU_PREFS.name === 'You' ? '' : global.SWU_PREFS.name;
    body.appendChild(nameInput);
    body.appendChild(el('div', 'artopt-desc',
      'Shown on the board and in the game log. Leave blank for "You".'));

    body.appendChild(el('h3', 'sect', 'Opponent difficulty'));
    var diffWrap = el('div', 'swatches');
    [['padawan', 'Padawan'], ['standard', 'Standard'], ['sith', 'Sith']].forEach(function (d) {
      var b = el('button', 'swatch diff' + ($('difficulty').value === d[0] ? ' on' : ''), d[1]);
      b.style.setProperty('--sw', 'var(--accent)');
      b.onclick = function () {
        $('difficulty').value = d[0];
        global.SWU_AI.setDifficulty(d[0]);
        Array.prototype.forEach.call(diffWrap.children, function (c) { c.classList.remove('on'); });
        b.classList.add('on');
      };
      diffWrap.appendChild(b);
    });
    body.appendChild(diffWrap);
    body.appendChild(el('div', 'artopt-desc', 'Takes effect on the next new game.'));

    body.appendChild(el('h3', 'sect', 'Accent colour'));
    var swatches = el('div', 'swatches');
    var chosenAccent = global.SWU_PREFS.accent;
    global.SWU_PREFS.ACCENTS.forEach(function (a) {
      var b = el('button', 'swatch accent' + (a.id === chosenAccent ? ' on' : ''));
      b.style.setProperty('--sw', a.value);
      b.title = a.name;
      b.appendChild(el('i'));
      b.appendChild(el('span', null, a.name));
      b.onclick = function () {
        chosenAccent = a.id;
        global.SWU_PREFS.save({ name: global.SWU_PREFS.name, accent: a.id });
        Array.prototype.forEach.call(swatches.children, function (c) { c.classList.remove('on'); });
        b.classList.add('on');
      };
      swatches.appendChild(b);
    });
    body.appendChild(swatches);

    // --- card art ----------------------------------------------------------
    body.appendChild(el('h3', 'sect', 'Card art'));
    var note = el('p', 'muted-note');
    note.textContent = 'No images ship with the app. Point it at a card source and they load ' +
      'straight in your browser — nothing is stored in the project.';
    body.appendChild(note);

    var form = el('div', 'artform');
    [['off', 'Text cards only', 'The default. Clean, fast, and always works.'],
     ['local', 'Local folder', 'Reads img/<card-id>.png next to index.html. See img/README.md for the ids.'],
     ['template', 'URL template', 'A pattern such as https://your-source.example/cards/{id}.png']
    ].forEach(function (row) {
      var label = el('label', 'artopt');
      var radio = document.createElement('input');
      radio.type = 'radio'; radio.name = 'artmode'; radio.value = row[0];
      radio.checked = cfg.mode === row[0];
      label.appendChild(radio);
      var txt = el('div');
      txt.appendChild(el('div', 'artopt-name', row[1]));
      txt.appendChild(el('div', 'artopt-desc', row[2]));
      label.appendChild(txt);
      form.appendChild(label);
    });

    var input = document.createElement('input');
    input.type = 'text';
    input.className = 'artinput';
    input.placeholder = 'https://your-source.example/cards/{id}.png';
    input.value = cfg.template || '';
    form.appendChild(input);

    var presetRow = el('div', 'swatches');
    global.SWU_ART.PRESETS.forEach(function (preset) {
      var b = el('button', 'swatch', 'Use ' + preset.name);
      b.style.setProperty('--sw', 'var(--accent)');
      b.onclick = function () {
        input.value = preset.template;
        var radio = form.querySelector('input[name=artmode][value=template]');
        if (radio) radio.checked = true;
      };
      presetRow.appendChild(b);
    });
    form.appendChild(presetRow);
    form.appendChild(el('div', 'artopt-desc',
      'Placeholders: {id} {name} {slug} {set} {number}. Anything that fails to load falls ' +
      'back to the text card.'));

    // --- card numbers ------------------------------------------------------
    // A {set}/{number} template needs each card's collector number, which the
    // decklist does not carry. Paste a deck export and they are read off it.
    var deckCards = [global.SWU_CARDS.LEADER, global.SWU_CARDS.BASE]
      .concat(global.SWU_CARDS.DECK)
      .map(function (d) { return { id: d.id, name: d.name }; });
    var have = Object.keys(cfg.numbers || {}).length;
    var pendingNumbers = null;

    form.appendChild(el('h3', 'sect', 'Card numbers'));
    var status = el('div', 'artopt-desc', have
      ? 'Stored for ' + have + ' of ' + deckCards.length + ' cards.'
      : 'None stored. A {set}/{number} template needs these.');
    form.appendChild(status);

    var paste = document.createElement('textarea');
    paste.className = 'artinput paste';
    paste.rows = 4;
    paste.placeholder = 'Paste your deck export here (JSON or a text list)';
    form.appendChild(paste);

    var match = el('button', 'btn', 'Read numbers from export');
    match.onclick = function () {
      var text = paste.value.trim();
      if (!text) { status.textContent = 'Paste an export first.'; return; }
      var result = global.SWU_ART.importDeckNumbers(text, deckCards);
      if (!result.matched.length) {
        status.textContent = 'No cards matched — that export has no card names ' +
          'with set and number next to them.';
        return;
      }
      pendingNumbers = result.numbers;
      status.textContent = 'Matched ' + result.matched.length + ' of ' + deckCards.length +
        ' cards.' + (result.unmatched.length ? ' Missing: ' + result.unmatched.join(', ') : '') +
        ' Press Save to keep them.';
    };
    form.appendChild(match);

    var save = el('button', 'btn primary', 'Save');
    save.onclick = function () {
      var mode = form.querySelector('input[name=artmode]:checked').value;
      var patch = { mode: mode, template: input.value.trim() };
      if (pendingNumbers) patch.numbers = pendingNumbers;
      global.SWU_ART.save(patch);
      global.SWU_PREFS.save({ name: nameInput.value, accent: chosenAccent });
      applyIdentity();
      $('modal').hidden = true;
      render();
    };
    form.appendChild(save);
    body.appendChild(form);
    $('modal').hidden = false;
  }

  function boot() {
    global.SWU_ART.load();
    global.SWU_PREFS.load();
    buildStars();
    global.addEventListener('resize', syncDockHeight);
    $('new-game').onclick = newGame;
    $('show-deck').onclick = showDeck;
    $('show-settings').onclick = showSettings;
    $('modal-close').onclick = function () { $('modal').hidden = true; };
    $('modal').onclick = function (e) { if (e.target === $('modal')) $('modal').hidden = true; };
    $('difficulty').onchange = function () { global.SWU_AI.setDifficulty($('difficulty').value); };
    newGame();
  }

  // Scripts may be injected after parsing (e.g. when hosted), so DOMContentLoaded
  // can already have fired by the time we get here.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
