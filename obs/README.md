# TechFitDad — OBS Broadcast Kit

A YouTube-ready overlay pack for recording. Everything is plain HTML/CSS/JS with **no
network requests** — no web fonts, no CDNs, no build step — so it runs on an air-gapped
lab box exactly like the rest of this repo.

Open **`index.html`** in a browser first: it previews every scene, switches brand, and
gives you a copy-paste URL for each one.

---

## The one rule that trips people up

OBS Browser sources have a **“Local file”** checkbox. If you tick it, **query parameters
are stripped** and every scene falls back to its defaults.

So: leave **“Local file” unchecked** and paste a full `file://` URL into the **URL** field:

```
file:///home/nate/stig-ai-lab/obs/starting-soon.html?mins=5&title=Starting%20Soon
```

`index.html` builds these for you — edit the query string on a card, hit **Copy OBS URL**.

---

## Brand

Colour and ink live in a token layer under `brands/`, loaded at runtime by `brand.js`
from `?brand=<name>` (default `techfitdad`).

| Brand | Palette |
|---|---|
| `techfitdad` *(default)* | volt `#c2f53f` + cyan `#35d6f5` on deep navy |
| `stig` | compliance green `#00e08a` + cyan `#22d3ee` — the STIG AI Lab look |

```
starting-soon.html?brand=stig
```

**The volt palette is a starting proposal, not your confirmed brand colours.** To set
your real ones, open `brands/techfitdad.css` and change the two hex values at the top,
then update the `rgba()` steps below them to the same colour at those alphas. Nothing
else in the pack hardcodes a brand colour — that one file re-skins all eight scenes.

Add another identity by copying that file to `brands/<name>.css` and loading `?brand=<name>`.

### Wordmark

The full-screen cards (starting soon, BRB, outro) carry a wordmark, top-left:

| Param | Default | Notes |
|---|---|---|
| `brandname` | `TECHFITDAD` | the wordmark text |
| `accent` | `FIT` | the substring painted in the brand colour |
| `mark` | `TF` | the square block before the name |
| `logo` | — | path to an image, replaces the `TF` block: `logo=logo.png` |
| `tagline` | — | optional line after a divider |
| `wordmark` | `on` | `off` hides it |

Drop a real logo file next to the HTML and pass `?logo=yourlogo.png` — a square PNG or
SVG with transparency, 80px or larger.

---

## Scenes

| File | Size | What it's for |
|---|---|---|
| `starting-soon.html` | 1920×1080 | Opening hold card — countdown, boot log, agenda tiles |
| `scene-card.html` | 1920×1080 | Chapter break. `bg=clear` = translucent slab over a screen share |
| `topic-bar.html` | 1920×1080 (transparent) | Top strip — REC dot, elapsed timer, chapter, progress |
| `lower-third.html` | 1920×1080 (transparent) | Name/role card that wipes in and hides itself |
| `camera-frame.html` | match your webcam | Corner brackets, scan sweep, label chip |
| `brb.html` | 1920×1080 | Break card with countdown |
| `outro.html` | 1920×1080 | Closing card — end-screen guides, optional before → after metric |
| `thumbnail.html` | 1280×720 | Not an overlay — screenshot it for a thumbnail |

Shared: `theme.css` · `brands/*.css` · `brand.js` · `params.js` · `pipeline.js` ·
`ticker.js` · `wordmark.js`

### Parameters

Everything is driven by the query string. Lists use `|` as the separator.

**starting-soon** — `mins` `title` `sub` `kicker` `host` `done` `agenda` `log` `ticker`

- `agenda=01:Today's build:brand|02:The walkthrough:c2|03:Q &amp; A:c3` — three tiles as
  `value:label:tone`, tone being `brand`, `c1`, `c2` or `c3`. Labels can't contain a colon.
  It doubles as a severity readout: `agenda=14:Cat I:c1|122:Cat II:c2|69:Cat III:c3`.
- `log=ok|lab up|warn|coffee low` — each line is `tone|text`, tone being `ok`, `warn`,
  `err`, `p` or empty.

**scene-card** — `num` `title` `sub` `step` (1–6) `phases` `bg` (`solid`|`clear`) `pipe` (`on`|`off`) `hold` (secs, `0` = stay)

**topic-bar** — `chapter` `topic` `step` `phases` `rec` (`on`|`off`) `pipe` (`on`|`off`)

**lower-third** — `name` `role` `meta` `pos` (`bl`|`br`|`tl`|`tr`) `dur` (secs, `0` = stay)

**camera-frame** — `label` `dot` (`rec`|`ok`|`warn`) `tag` (`on`|`off`) `scan` (`on`|`off`)

**brb** — `mins` `title` `sub` `status` `status2` `step` `done` `ticker`

**outro** — `title` (accepts `<br>`) `sub` `kicker` `before` `after` `beforecap` `aftercap`
`score` (`on`|`off`) `link1` `link2` `guides` (`on`|`off`)

**thumbnail** — `head` (`line1|line2`) `kicker` `tag` `score` `scorecap` `cat1` `cat2` `cat3`

Chapters default to `Intro · Setup · Build · Break · Fix · Wrap`; `step` highlights where
you are. For a STIG AI Lab run, pass the agent flow instead:

```
scene-card.html?brand=stig&phases=Scan|Analyse|Approve|Remediate|Apply|Validate&step=3
```

---

## Suggested scene collection

Canvas: **1920×1080**, 30 or 60 fps.

| Scene | Sources (top to bottom) |
|---|---|
| **Starting Soon** | `starting-soon.html` |
| **Talking Head** | `lower-third.html` · `camera-frame.html` · Video Capture Device |
| **Terminal** | `topic-bar.html` · `camera-frame.html` + camera (corner) · Window/Display Capture |
| **Chapter** | `scene-card.html` |
| **BRB** | `brb.html` |
| **Outro** | `outro.html` |

Add each overlay as a Browser source at **1920×1080** with **“Shutdown source when not
visible”** and **“Refresh browser when scene becomes active”** both ticked. That second one
matters: it restarts the countdowns, the wipe-in animations and the elapsed timer every
time you cut to the scene.

For the camera frame, set the browser source to the *same* pixel size as your webcam
source and stack it directly on top.

### Reusing overlays across scenes

Don't copy a browser source — right-click in **Sources → Add → Browser → Add Existing**,
or put the overlay in its own scene and nest that scene. One instance means one timer.

### Changing a topic or step mid-recording

Right-click the browser source → **Properties**, edit the query string, **OK**. The source
reloads with the new values. For fast switching, make one source per chapter and toggle
visibility — or bind scene hotkeys under **Settings → Hotkeys**.

---

## Recording settings for YouTube

- **Output mode:** Advanced → Recording
- **Format:** MKV (remux to MP4 afterwards — MKV survives a crash)
- **Encoder:** NVENC / QSV / AMF if you have it, else x264 `veryfast`
- **Rate control:** CQP 18–20 (NVENC) or CRF 18–20 (x264)
- **Keyframe interval:** 2s

Terminal work is mostly static text, so high-quality/low-motion settings are cheap here.
Record 1080p60 if you scroll logs a lot.

## Thumbnails

`thumbnail.html` is a 1280×720 template. The headline is measured and shrunk to fit, so
any length lands on the layout instead of orphaning a word. The lower third of the frame
is deliberately left clear for a face cutout you composite in your editor.

Open it at exactly 1280×720 and screenshot, or point a 1280×720 browser source at it and
use **right-click → Screenshot (Source)** in OBS for a clean PNG with no browser chrome.

```
file:///home/nate/stig-ai-lab/obs/thumbnail.html?head=I%20broke%20my%20homelab%7Con%20purpose&score=94%25&scorecap=uptime&tag=day%2012
```

## Type

Fonts are system stacks — JetBrains Mono / Fira Code for mono and Inter / Segoe / system
sans for display, each falling back to whatever the machine has. Install JetBrains Mono
and Inter for the intended look; nothing breaks offline if you don't.
