# Vader Sealed — Practice App

A local, offline app for playing **Vader Sealed — A Lawless Time** against a computer
opponent, so you can drill the deck's sequencing before a real game.

No build step, no dependencies, no network. Open the file and play.

```bash
# Either just open it:
xdg-open index.html          # macOS: open index.html

# ...or serve it, if you prefer a http:// origin:
python3 -m http.server 8000 --directory .
# then visit http://localhost:8000/
```

Node is only needed for the test scripts, not to play.

---

## Your deck

Exactly the list you built, 30 cards, from `js/cards.js`:

- **Leader:** Darth Vader — Unstoppable (LAW 011), 7 cost, 6/8, Aggression + Villainy
- **Base:** Partisan Hideout, 27 HP, Cunning
- 24 units · 5 events · 1 upgrade · aspects covered: Aggression, Villainy, Cunning

Every card's ability is implemented, including the ones that make the deck tick:

| Card | What the app does |
|---|---|
| Vader (leader ability) | Exhaust + discard a card from hand → 1 damage to a unit or base |
| Vader (Epic Action) | Free deploy once you control 7+ resources |
| Vader (deployed, On Attack) | Discard any number of cards → that much damage to a unit or base |
| Salvaged Blaster | +2/+0 on a non-Vehicle unit; replayable from discard if it was discarded this phase |
| Vult Skerris's Defender | Shield if you discarded this phase; On Attack ping + exhaust a space unit |
| Sebulba's Podracer | Offers to ready itself whenever you discard from your deck (once per round) |
| Improvise | Reveals your top card, offers to play it for 1 less or discard it |
| You Hold This | Hands a unit to the opponent, then 4 damage to another unit in that arena |
| Daring Delve | Mills 2, offers back an Aggression card |
| Qui-Gon Jinn | Look at top 3, may discard 1 — on play and on every attack |
| Arvel Skeen | Spends Credit tokens for 1 damage, on play and on attack |
| Champion's KT9 Podracer | Creates the Credit token Arvel wants |

Keywords implemented: **Raid N, Sentinel, Saboteur, Ambush, Hidden**, plus Shield and
Experience tokens and Credit tokens.

## The opponent

`js/opponent-deck.js` is a **generic sparring deck** (Command / Vigilance, 27 HP base).
Those are deliberately *not* real Star Wars Unlimited cards — they are plain practice
bodies with an average sealed curve, keyword mix and three Sentinels, so you are
drilling your own sequencing rather than memorising one specific opponent list.

To practise against a real list instead, replace `DECK`, `LEADER` and `BASE` in that
file. The definition format and the available hooks are documented by example in
`js/cards.js`.

### Difficulty

One honest knob — how often the opponent takes a random legal action or makes a sloppy
in-prompt choice. Neither side gets hidden bonuses.

| Setting | AI sloppiness | Deck win rate when *both* sides are played by the built-in heuristic |
|---|---|---|
| Padawan | 40% | ~53% |
| Standard | 15% | ~45% |
| Sith | 0% | ~42% |

Those numbers are the deck piloted by a naive bot. Playing it properly — holding Vader's
ping for a kill, respecting the resource drop, using Hidden bodies to tempo — should put
you well above them. Measure it yourself with `node test/balance.js 400`.

---

## How to play

- **Your turn is one action**, then the opponent acts. Highlights tell you what is legal:
  - gold border on a hand card → you can afford to play it
  - green border on your unit → it can attack
  - blue border → it is a legal target for the choice you are being asked to make
- Side panel buttons cover everything else: deploy Vader, his Epic Action, his ping,
  taking the initiative, and passing.
- When both players pass, the round ends: you resource a card, both players draw 2, and
  everything readies.
- First base to 0 loses. Your base is 27 HP; so is theirs.

### Rules implemented

Round structure (action phase → regroup phase), initiative, resourcing, aspect penalties
(+2 per uncovered aspect icon), units entering play exhausted, arena restrictions,
Sentinel forcing attacks, Saboteur ignoring Sentinel and stripping shields, Raid against
bases, Ambush, Hidden, simultaneous combat damage, shields absorbing a whole source of
damage, leader deploy (paid or via an Epic Action), and 3 damage to your own base when
you cannot draw.

### Deliberate simplifications

These are the places the app is knowingly looser than the comprehensive rules — worth
knowing before you carry a habit to a real table:

1. **Hidden** is implemented as "cannot be attacked during the round it was played".
2. **Initiative** — the token can be claimed once per round as an action; claiming it
   does not end your turns, and whoever holds it at round end goes first next round.
3. **Passing** — any non-pass action clears both pass flags, so the phase ends only on
   two consecutive passes.
4. **The base's Epic Action** (ignore 1 aspect penalty) is not wired to a button, because
   this deck's aspects are fully covered and it would never change a cost.
5. No "when defeated" triggers fire from a leader returning to the leader zone, and
   upgrade cards go to the discard pile when played rather than being tracked as a
   physical card in play.
6. There is no undo, no timing window for reactions, and no deck validation beyond what
   is in the card files.

---

## Tests

```bash
node test/smoke.js 200     # fuzz: random-but-legal player vs the AI, catches crashes/stuck prompts
node test/balance.js 400   # AI vs AI, reports the deck's win rate and average game length
```

`smoke.js` fails loudly on a crash, a stuck prompt, a position with no legal action, or a
game that will not terminate. `balance.js` is the knob to re-check after editing either
deck file.

## Files

```
index.html            markup and zone layout
styles.css            dark board theme
js/cards.js           your leader, base and 30-card deck, with every ability
js/opponent-deck.js   the generic sparring deck (swap this out)
js/engine.js          rules engine: phases, resources, combat, prompts
js/ai.js              opponent heuristic and difficulty
js/ui.js              rendering and click handling
test/                 fuzz and balance harnesses
```
