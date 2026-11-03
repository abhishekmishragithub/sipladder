# Engineering paper

SIP ladders inherit the visual grammar of RFC sequence diagrams: endpoints,
vertical lifelines, directional messages and elapsed time. The primary surface
is warm technical paper, with blue drafting ink and a 16 px faint grid confined
to the ladder plot. The alternate theme is a blue-slate blueprint. The existing
OS preference and theme toggle still choose the theme; no preference is stored.

## Tokens

| Token          | Paper       | Blueprint   | Role                                                |
| -------------- | ----------- | ----------- | --------------------------------------------------- |
| `--bg`         | `#f5f1e7`   | `#182c3a`   | Worksheet                                           |
| `--surface`    | `#ebe6d9`   | `#203746`   | Inspector, conversation index, drop target          |
| `--ink`        | `#24343d`   | `#edf0e7`   | UI and raw text                                     |
| `--muted`      | `#575f61`   | `#b3c3c9`   | Secondary text, timing, endpoints, RTP observations |
| `--accent`     | `#175783`   | `#8bc7ed`   | Requests, 1xx, focus, inspection seal               |
| `--good`       | `#24623e`   | `#99d3ac`   | 2xx responses only                                  |
| `--bad`        | `#a33228`   | `#ffaaa0`   | 4xx–6xx, diagnoses, warnings, errors                |
| `--redirect`   | `#805218`   | `#e7c18b`   | 3xx responses                                       |
| `--line`       | `#7c817c`   | `#718995`   | Rules, lifelines, control borders                   |
| `--grid`       | `#1757830b` | `#8bc7ed0c` | Plot grid                                           |
| `--wash`       | `#17578310` | `#8bc7ed16` | Hover and selection                                 |
| `--annotation` | `#a332280b` | `#ffaaa00b` | Grease-pencil annotation ground                     |

Provisional arrows are dashed; failures use a heavier stroke. Status words
remain visible so color is never the only signal. Diagnoses use a red margin
stroke and broken underline, like marks on a drawing rather than badges. RTP
remains a neutral observation in the summary: advertised/observed media is not
an independently proven success. There are no RTP arrows in the existing SVG.
The privacy promise is a double-rule inspection stamp, without animation.

## Typography and dimensions

The UI stack is `Segoe UI`, `Helvetica Neue`, Arial, sans-serif: familiar humanist
and neo-grotesque system faces with compact, readable engineering chrome. No
font is downloaded or bundled (zero added bytes); this also preserves the
existing `font-src 'none'` CSP. Generic system monospace is reserved for SIP,
Call-IDs, endpoints, raw messages, sequence metadata and timing labels.

| Use                            | Size / line height            |
| ------------------------------ | ----------------------------- |
| Intro heading                  | responsive 40–68 px / 1.08    |
| Capture heading                | 30 px / 1.08                  |
| Intro explanation              | 17 px / 1.7 (15 px on mobile) |
| Drop heading                   | 20 px (16 px on mobile)       |
| Conversation ID                | 16 px mono                    |
| Diagnoses                      | 13 px / 1.7, sans             |
| Controls and summaries         | 11–13 px, sans                |
| Raw SIP                        | 11 px / 1.8, mono             |
| SVG message / metadata / ruler | 11 / 9 / 9 px, mono           |
| Section labels                 | 10 px, tracked sans           |

Layout spacing follows a 4 px module (4, 8, 12, 16, 20, 24, 32, 40, 48).
Corners use a consistent 2 px radius. Summaries form a ruled strip rather than
separate cards. The original responsive column breakpoints and scrollable
ladder remain; endpoint and message geometry is unchanged. Ruler ticks add
relative seconds alongside the existing per-message metadata; vertical spacing
still represents message order, not a proportional time axis.

## Contrast and verification

Run `npx tsx scripts/check-contrast.ts`. It reads the actual CSS tokens and uses
WCAG sRGB relative luminance, compositing translucent backgrounds. These are
the minimum ratios across paper, panel, grid, selection and annotation grounds:

| Foreground                 | Paper   | Blueprint |
| -------------------------- | ------- | --------- |
| Text ink                   | 10.32:1 | 10.36:1   |
| Muted text                 | 5.24:1  | 6.58:1    |
| Drafting blue / focus      | 6.18:1  | 6.54:1    |
| Success green              | 5.83:1  | 6.98:1    |
| Failure red                | 5.54:1  | 6.55:1    |
| Redirect ochre             | 5.37:1  | 7.05:1    |
| Rules / control boundaries | 3.19:1  | 3.25:1    |

Every text pair exceeds AA's 4.5:1 requirement; control boundaries exceed 3:1.
The faint decorative grid is deliberately below that threshold. Keyboard focus
uses a two-pixel blue outline; SVG message rows also receive an explicit focus
stroke. Reduced-motion disables transitions and smooth scrolling.

All 41 parser/summary/redaction tests and eight golden text ladders pass without
snapshot updates. Production build and format checks pass. Playwright uses the
existing synthetic capture and screenshot workflow; the GIF uses the existing
Pillow conversion with paper-colored letterboxing. Browser checks cover both
themes, reduced motion, real drop/worker parsing, keyboard selection, text table,
clipboard redaction, blocked page/worker fetches and external images, invalid
files, replacement, pagination and mobile overflow. Screenshots include a
blueprint workspace for visual inspection.

Production CSS is 10.60 kB (2.93 kB gzip, Vite decimal units). Runtime dependencies
remain zero. Parsing, features, URLs, exported text and CSP are unchanged.
