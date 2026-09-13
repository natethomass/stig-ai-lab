# Card art (optional, not included)

This folder is empty on purpose. Card images are copyrighted by their publisher,
so none are bundled with this app or committed to this repository.

If you have images you are entitled to use, drop them here named by card id and
switch **Card art → Local folder** in the app:

```
img/savareen-survivor.png
img/darth-vader.png
img/partisan-hideout.png
```

The ids are the `id` fields in `js/cards.js` and `js/opponent-deck.js`.

## Fetching in bulk

`tools/fetch-art.js` downloads images for every card in the deck into this folder,
from a source you name. It runs on your machine, writes only here, and commits
nothing:

```bash
# If you know the source's URL pattern:
node tools/fetch-art.js --template "https://your-source.example/cards/{slug}.png"

# If you downloaded the source's card index as JSON:
node tools/fetch-art.js --index cards.json
node tools/fetch-art.js --index cards.json --url-field art.front   # if auto-detect misses
```

It matches cards by name, follows redirects, rejects non-image responses, skips
files you already have, and pauses between requests. `--dry-run` shows what it
would do. Check the source's terms of use first and leave the delay alone — this
is a 30-card fetch, not a scraper.

Alternatively pick **Card art → URL template** and give a pattern such as
`https://your-source.example/cards/{id}.png`. Supported placeholders are
`{id}`, `{name}`, `{slug}`, `{set}` and `{number}`. Images load directly in your
browser; nothing is written into the repo. Any image that fails to load falls
back to the text card, so a wrong pattern degrades quietly rather than breaking
the game.
