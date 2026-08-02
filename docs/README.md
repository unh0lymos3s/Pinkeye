# Pinkeye product page

The public "coming soon" page for Pinkeye, served straight out of this directory by GitHub Pages.

It is **already compiled**: plain HTML, one stylesheet, one ES module, and local assets. No
framework, no bundler, no `node_modules`, and no third-party requests at runtime — what's committed
here is exactly what gets served. It is entirely separate from the operator UI in `web/` (that one
is a Next.js app that talks to the control plane); nothing on this page can reach an API.

```
docs/
├── index.html                 the page (wordmark SVG is pre-rendered into it)
├── styles.css                 design tokens + layout, lifted from web/app/globals.css
├── eye-orb.js                 the 3D eye, ported from web/app/EyeOrb.tsx (no React)
├── favicon.svg
├── fonts/                     IBM Plex Mono 500/600, latin subset (SIL OFL 1.1)
├── vendor/                    three.js r0.185.1 ESM build (MIT — see THREE-LICENSE)
├── tools/build-banner.mjs     regenerates the wordmark inside index.html
└── .nojekyll                  serve files as-is; don't run them through Jekyll
```

## Enabling GitHub Pages

Once this is on `main`: **Settings → Pages → Source: "Deploy from a branch" → Branch: `main`,
Folder: `/docs` → Save.** The page appears at `https://unh0lymos3s.github.io/Pinkeye/` a minute or
two later. No Actions workflow needed.

Every path in `index.html` is relative (`./styles.css`, `./eye-orb.js`, …), so the site works
unchanged under that `/Pinkeye/` sub-path, at a custom domain, or in a subdirectory of any other
static host.

## Previewing locally

```sh
python3 -m http.server 8080 --directory docs   # then open http://localhost:8080/
```

Use a server rather than opening `index.html` directly — `file://` blocks ES module imports, so the
eye won't load (the rest of the page will).

## Editing

- **Text, links, meta tags** — edit `index.html` directly.
- **Colors, spacing, type** — edit `styles.css`. The tokens at the top mirror `web/app/globals.css`.
- **The wordmark** — edit the art (or glyph font) in `tools/build-banner.mjs`, then run
  `node docs/tools/build-banner.mjs`. It rewrites only the `banner:start`/`banner:end` block in
  `index.html`. Don't hand-edit those `<rect>`s.
- **The eye** — `eye-orb.js` is a port of `web/app/EyeOrb.tsx`. They're deliberately identical;
  change both or they drift apart.
