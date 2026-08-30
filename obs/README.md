# OBS Broadcast Theme — STIG AI Lab

A YouTube-ready overlay pack for recording this project. Everything is plain HTML/CSS/JS
with **no network requests** — no web fonts, no CDNs, no build step — so it works on an
air-gapped RHEL box exactly like the lab itself.

Open **`index.html`** in a browser first: it previews every scene and gives you a
copy-paste URL for each one.

---

## The one rule that trips people up

OBS Browser sources have a **“Local file”** checkbox. If you tick it, **query parameters
are stripped** and every scene falls back to its defaults.

So: leave **“Local file” unchecked** and paste a full `file://` URL into the **URL** field:

```
file:///home/nate/stig-ai-lab/obs/starting-soon.html?mins=5&title=Starting%20Soon
```

`index.html` builds these URLs for you — edit the query string on a card and hit
**Copy OBS URL**.

---

## Scenes

| File | Size | What it's for |
|---|---|---|
| `starting-soon.html` | 1920×1080 | Opening hold card — countdown, live boot log, CAT I/II/III readout |
| `scene-card.html` | 1920×1080 | Chapter break. `bg=clear` makes it a translucent slab over a screen share |
| `topic-bar.html` | 1920×1080 (transparent) | Persistent top strip — REC dot, elapsed timer, chapter, pipeline position |
| `lower-third.html` | 1920×1080 (transparent) | Name/role card that wipes in and hides itself |
| `camera-frame.html` | match your webcam | Corner brackets, scan sweep, label chip |
| `brb.html` | 1920×1080 | Break card with its own countdown |
| `outro.html` | 1920×1080 | Closing card — before → after compliance score, end-screen guides |
| `thumbnail.html` | 1280×720 | Not an overlay — screenshot it for a channel-consistent thumbnail |

Shared files: `theme.css` (all design tokens), `params.js`, `pipeline.js`, `ticker.js`.

### Parameters

Everything is driven by the query string. Lists use `|` as the separator.

**starting-soon** — `mins` `title` `sub` `kicker` `host` `cat1` `cat2` `cat3` `done` `log` `ticker`
Log lines take a severity prefix: `ok|…`, `warn|…`, `err|…`, `p|…`.

**scene-card** — `num` `title` `sub` `step` (1–6) `phases` `bg` (`solid`|`clear`) `pipe` (`on`|`off`) `hold` (seconds, `0` = stay)

**topic-bar** — `chapter` `topic` `step` `phases` `rec` (`on`|`off`) `pipe` (`on`|`off`)

**lower-third** — `name` `role` `meta` `pos` (`bl`|`br`|`tl`|`tr`) `dur` (seconds, `0` = stay)

**camera-frame** — `label` `dot` (`rec`|`ok`|`warn`) `tag` (`on`|`off`) `scan` (`on`|`off`)

**brb** — `mins` `title` `sub` `step` `done` `ticker`

**outro** — `title` (accepts `<br>`) `sub` `kicker` `before` `after` `link1` `link2` `guides` (`on`|`off`)

**thumbnail** — `head` (`line1|line2`) `kicker` `tag` `score` `scorecap` `cat1` `cat2` `cat3`

The six pipeline phases default to the agent flow in the main README —
Scan → Analyse → Approve → Remediate → Apply → Validate. `step` highlights where you are;
`phases=A|B|C` replaces the labels entirely.

---

## Suggested scene collection

Canvas: **1920×1080**, 30 or 60 fps.

| Scene | Sources (top to bottom) |
|---|---|
| **Starting Soon** | `starting-soon.html` |
| **Talking Head** | `lower-third.html` · `camera-frame.html` · Video Capture Device |
| **Terminal** | `topic-bar.html` · `camera-frame.html` + camera (corner) · Window/Display Capture of your RHEL VM |
| **Chapter** | `scene-card.html` |
| **BRB** | `brb.html` |
| **Outro** | `outro.html` |

Add each overlay as a Browser source at **1920×1080** with **“Shutdown source when not
visible”** and **“Refresh browser when scene becomes active”** both ticked. That second one
matters: it restarts the countdowns, the wipe-in animations and the elapsed timer every
time you cut to the scene.

For the camera frame, set the browser source to the *same* pixel size as your webcam source
and stack it directly on top.

### Reusing overlays across scenes

Don't copy a browser source — right-click in **Sources → Add → Browser → Add Existing**,
or put the overlay in a Scene and nest that scene. One instance means one timer.

### Changing a topic or step mid-recording

Right-click the browser source → **Properties**, edit the query string, **OK**. The source
reloads with the new values. For fast switching, make one duplicated source per chapter and
toggle visibility — or bind scene hotkeys under **Settings → Hotkeys**.

---

## Recording settings for YouTube

- **Output mode:** Advanced → Recording
- **Format:** MKV (remux to MP4 afterwards — MKV survives a crash)
- **Encoder:** NVENC / QSV / AMF if you have it, else x264 `veryfast`
- **Rate control:** CQP 18–20 (NVENC) or CRF 18–20 (x264)
- **Keyframe interval:** 2s

Terminal work is mostly static text, so a high-quality/low-motion setting is cheap here.
Record at 1080p60 if you'll be scrolling logs a lot.

---

## Making it yours

All colour and type live in `:root` at the top of `theme.css`:

```css
--brand:   #00e08a;   /* compliance green — the accent everywhere */
--brand-2: #22d3ee;   /* scanner cyan — gradient partner */
--cat1: #ff4d61;      /* CAT I  */
--cat2: #ffb020;      /* CAT II */
--cat3: #5aa9ff;      /* CAT III */
```

Change those five and the whole pack re-skins. Fonts are system stacks — JetBrains Mono /
Fira Code if installed, otherwise the platform monospace — so nothing breaks offline.

## Thumbnails

Open `thumbnail.html` at exactly 1280×720 and screenshot it, or point a 1280×720 browser
source at it and use **right-click → Screenshot (Source)** in OBS, which writes a clean PNG
with no browser chrome.

```
file:///home/nate/stig-ai-lab/obs/thumbnail.html?head=I%20let%20an%20AI%7Charden%20RHEL%2010&score=43%25&tag=205%20findings
```
