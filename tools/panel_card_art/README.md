# Panel card artwork

The panel card (`custom_components/ldata/www/ldata-panel-card.js`) is not drawn with CSS. It is assembled from ray-traced images in `custom_components/ldata/www/img`, and those images are rendered from the 3D model in this folder.

The model was measured from Leviton's straight-on catalog photographs of the 2nd Gen smart breakers (LB120-ST, LB220-ST), the standard breaker (LB120-T) and the load center covers (LDC series), and the handle and LED behavior follows the "Handle operation and LED diagnostics" table in Leviton's 2nd Gen Smart Circuit Breakers spec sheet. No Leviton image is used in the artwork; the photographs were only the reference.

## Regenerating

```sh
python3 tools/panel_card_art/make_art.py
```

This renders every piece with Blender (about seven minutes on a recent laptop, CPU only), converts the renders to WebP, installs them in `custom_components/ldata/www/img`, and updates `ART_REV` in the card. `ART_REV` is the content hash of the images and is part of every image URL, so browsers fetch new artwork after an upgrade. `tests/test_panel_card_art.py` fails if the two drift apart.

You need:

- Blender 4.2 or newer. If it isn't on your `PATH`, set `BLENDER` to its executable.
- Python with Pillow, and the `cwebp` encoder (`brew install webp`, `apt install webp`).
- Arial, which the printed legends are set in. Set `LD_FONT_DIR` if it isn't in a standard location.

The breakers are rendered with the maker's name on them, as the real ones are (set in plain bold type, not Leviton's logo artwork). To render them without it, run with `LD_NO_BRAND=1`.

`make_art.py --build` skips rendering and rebuilds the WebP files from the renders already in `renders/` (or the folder named by `LD_RENDERS`).

## What gets rendered

| Files | What they are |
| --- | --- |
| `bk-{L,R}{1,2}{s,t}-{on,off,trip}` | One breaker in the left or right column, 1- or 2-pole, smart (`s`) or standard (`t`), in each handle position. Each image is one space tall plus a strip underneath that holds only the shadow the breaker casts on the space below it. |
| `fill-{L,R}`, `cap-{L,R}-{top,bot}` | The filler plate for an open space, and the dead front that closes the top and bottom of each column. |
| `frame`, `cover` | The embossed door surround and the cover plate. Both are samples that the card stretches as nine-slices, which is how one set of images fits any panel size. |
| `screw-a`, `screw-b`, `main-{on,off}` | Cover screws and the optional main breaker. |
| `hero-{1,2}{s,t}-{on,off,trip}` | The upright product shot shown in the breaker's detail sheet. |

## Changing the model

- `ld_scene.py` holds the model, materials, lighting and one render job per kind of piece. Measurements at the top of the file are in inches, taken from the photographs.
- The card places overlays (the rocker's click target, the status LED, the printed amp rating) from the same measurements. They are exported to `renders/geometry.json`; if you change one, update `G` at the top of the card to match.
- Every piece is lit by the same sun and dome with no falloff, so a flat surface renders to one flat color. That is what lets separately rendered pieces meet without visible joins; keep it that way if you change the lighting.
