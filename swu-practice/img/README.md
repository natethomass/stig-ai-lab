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

Alternatively pick **Card art → URL template** and give a pattern such as
`https://your-source.example/cards/{id}.png`. Supported placeholders are
`{id}`, `{name}`, `{slug}`, `{set}` and `{number}`. Images load directly in your
browser; nothing is written into the repo. Any image that fails to load falls
back to the text card, so a wrong pattern degrades quietly rather than breaking
the game.
