"""Visual style for the Streamlit dashboard: CSS and small HTML builders.

Responsibility: one place for the minimalist look (warm monochrome,
1px hairline borders, editorial serif headings, muted pastel status
badges), applied inside Streamlit through st.markdown, plus the theme
in .streamlit/config.toml.

Everything runs locally: fonts are system font stacks, so the browser
never fetches a web font, icon set or image from anywhere.

Every builder here HTML-escapes the values it is given. Incident notes,
device names, LLM answers and retrieved snippets are untrusted text and
must only ever reach the page through these builders or through
Streamlit's own escaped widgets, never through st.markdown, which would
render links and remote images inside them.
"""

from __future__ import annotations

from html import escape

INK = "#111111"
TEXT = "#2F3437"
MUTED = "#787774"
CANVAS = "#FBFBFA"
SURFACE = "#FFFFFF"
BONE = "#F7F6F3"
HAIRLINE = "#EAEAEA"

PASTELS = {
    "red": ("#FDEBEC", "#9F2F2D"),
    "blue": ("#E1F3FE", "#1F6C9F"),
    "green": ("#EDF3EC", "#346538"),
    "yellow": ("#FBF3DB", "#956400"),
    "gray": ("#F1F1EF", "#787774"),
}

VERDICT_COLOURS = {
    "blocked": "red",
    "suspicious": "yellow",
    "normal": "green",
    "idle": "gray",
}

SANS = "'SF Pro Display', 'Geist Sans', 'Helvetica Neue', 'Switzer', 'Segoe UI', sans-serif"
SERIF = "'Lyon Text', 'Newsreader', 'Iowan Old Style', 'Georgia', serif"
MONO = "'Geist Mono', 'SF Mono', 'JetBrains Mono', 'Cascadia Mono', 'Consolas', monospace"

CHART_PALETTE = ["#2F3437", "#1F6C9F", "#9F2F2D", "#346538", "#956400", "#787774"]

CSS = f"""
<style>
:root {{
  --ct-ink: {INK}; --ct-text: {TEXT}; --ct-muted: {MUTED};
  --ct-canvas: {CANVAS}; --ct-surface: {SURFACE}; --ct-bone: {BONE};
  --ct-hairline: {HAIRLINE};
}}
html, body, .stApp, [class*="css"], .stMarkdown, button, input, textarea, select {{
  font-family: {SANS};
  color: var(--ct-text);
}}
.stApp {{ background: var(--ct-canvas); }}
.block-container {{ max-width: 1080px; padding-top: 3.5rem; padding-bottom: 6rem; }}
h1, h2, h3 {{
  font-family: {SERIF} !important;
  color: var(--ct-ink) !important;
  letter-spacing: -0.025em;
  line-height: 1.1 !important;
  font-weight: 500 !important;
}}
h1 {{ font-size: 2.6rem !important; margin-bottom: 0.25rem !important; }}
h2 {{ font-size: 1.6rem !important; margin-top: 2.5rem !important; }}
h3 {{ font-size: 1.2rem !important; }}
p, li {{ line-height: 1.6; }}
code, kbd, .ct-mono {{ font-family: {MONO}; font-size: 0.85em; }}
[data-testid="stSidebar"] {{
  background: var(--ct-bone);
  border-right: 1px solid var(--ct-hairline);
}}
[data-testid="stSidebar"] [role="radiogroup"] label {{
  padding: 0.35rem 0.5rem; border-radius: 6px; width: 100%;
}}
[data-testid="stSidebar"] [role="radiogroup"] label:hover {{ background: rgba(0,0,0,0.04); }}
.stButton > button, .stFormSubmitButton > button, .stDownloadButton > button {{
  border-radius: 6px; border: 1px solid var(--ct-hairline);
  box-shadow: none; transition: transform 120ms ease, background 120ms ease;
}}
.stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primary"] {{
  background: var(--ct-ink); color: #FFFFFF; border-color: var(--ct-ink);
}}
.stButton > button[kind="primary"]:hover, .stFormSubmitButton > button[kind="primary"]:hover {{
  background: #333333; border-color: #333333; color: #FFFFFF;
}}
.stButton > button:active {{ transform: scale(0.98); }}
[data-testid="stExpander"] details {{
  border: none; border-bottom: 1px solid var(--ct-hairline); border-radius: 0;
}}
[data-testid="stDataFrame"], [data-testid="stTable"] {{
  border: 1px solid var(--ct-hairline); border-radius: 8px;
}}
hr {{ border-color: var(--ct-hairline); }}

@keyframes ct-enter {{
  from {{ opacity: 0; transform: translateY(12px); }}
  to {{ opacity: 1; transform: translateY(0); }}
}}
.ct-card {{
  background: var(--ct-surface); border: 1px solid var(--ct-hairline);
  border-radius: 8px; padding: 24px; margin-bottom: 16px;
  animation: ct-enter 600ms cubic-bezier(0.16, 1, 0.3, 1) both;
  transition: box-shadow 200ms ease;
}}
.ct-card:hover {{ box-shadow: 0 2px 8px rgba(0,0,0,0.04); }}
.ct-card.ct-amber {{ background: #FBF3DB; border-color: #F0E2B6; }}
.ct-card-title {{ font-weight: 600; color: var(--ct-ink); margin-bottom: 6px; }}
.ct-eyebrow {{
  font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.08em;
  color: var(--ct-muted); margin-bottom: 4px;
}}
.ct-lede {{ color: var(--ct-muted); font-size: 1.02rem; margin-bottom: 2.5rem; }}
.ct-value {{ font-size: 1.5rem; color: var(--ct-ink); font-weight: 500; line-height: 1.2; }}
.ct-hint {{ color: var(--ct-muted); font-size: 0.82rem; margin-top: 4px; }}
.ct-badge {{
  display: inline-block; border-radius: 9999px; padding: 2px 10px;
  font-size: 0.68rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;
}}
.ct-dot {{
  display: inline-block; width: 8px; height: 8px; border-radius: 9999px;
  margin-right: 8px; vertical-align: middle;
}}
.ct-row {{ display: flex; justify-content: space-between; align-items: baseline; gap: 16px; }}
.ct-text {{ white-space: pre-wrap; line-height: 1.6; }}
.ct-meter {{ position: relative; height: 6px; background: var(--ct-bone);
  border: 1px solid var(--ct-hairline); border-radius: 4px; margin: 10px 0 6px; }}
.ct-meter-fill {{ position: absolute; left: 0; top: 0; bottom: 0; border-radius: 4px; }}
.ct-meter-mark {{
  position: absolute; top: -5px; bottom: -5px; width: 1px; background: var(--ct-ink);
}}
.ct-kv {{ display: grid; grid-template-columns: 180px 1fr; row-gap: 6px; column-gap: 16px; }}
.ct-kv div:nth-child(odd) {{ color: var(--ct-muted); }}
</style>
"""


def badge(label: str, colour: str = "gray") -> str:
    background, foreground = PASTELS.get(colour, PASTELS["gray"])
    return (
        f'<span class="ct-badge" style="background:{background};color:{foreground}">'
        f"{escape(label)}</span>"
    )


def verdict_badge(verdict: str) -> str:
    return badge(verdict, VERDICT_COLOURS.get(verdict, "gray"))


def status_dot(on: bool) -> str:
    colour = PASTELS["green"][1] if on else PASTELS["red"][1]
    return f'<span class="ct-dot" style="background:{colour}"></span>'


def text_block(text: str) -> str:
    """Untrusted text, escaped, with its line breaks kept."""
    return f'<div class="ct-text">{escape(text)}</div>'


def stat_card(label: str, value: str, hint: str = "") -> str:
    hint_html = f'<div class="ct-hint">{escape(hint)}</div>' if hint else ""
    return (
        f'<div class="ct-card"><div class="ct-eyebrow">{escape(label)}</div>'
        f'<div class="ct-value">{escape(value)}</div>{hint_html}</div>'
    )


def card(body_html: str, *, title: str = "", eyebrow: str = "", amber: bool = False) -> str:
    """body_html must already be built from escaped parts."""
    classes = "ct-card ct-amber" if amber else "ct-card"
    eyebrow_html = f'<div class="ct-eyebrow">{escape(eyebrow)}</div>' if eyebrow else ""
    title_html = f'<div class="ct-card-title">{escape(title)}</div>' if title else ""
    return f'<div class="{classes}">{eyebrow_html}{title_html}{body_html}</div>'


def key_values(pairs: list[tuple[str, str]]) -> str:
    cells = "".join(
        f"<div>{escape(key)}</div><div>{escape(value)}</div>" for key, value in pairs
    )
    return f'<div class="ct-kv">{cells}</div>'


def typing_box(passage: str) -> str:
    """A self-contained page: the passage, a box to type it in, and live stats.

    Speed and accuracy are worked out in the browser and shown there only.
    The page has no network code at all, so what is typed never leaves the
    browser; the runtime records the timing separately, through Raw Input.
    Pasting is blocked because pasted text produces no keystrokes to learn
    from.
    """
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><style>
body {{ margin: 0; font-family: {SANS}; color: {TEXT}; background: transparent; }}
.passage {{ font-family: {SERIF}; font-size: 1.12rem; line-height: 1.7; color: {INK};
  background: {SURFACE}; border: 1px solid {HAIRLINE}; border-radius: 8px; padding: 18px 20px; }}
textarea {{ box-sizing: border-box; width: 100%; height: 150px; margin-top: 14px;
  padding: 14px 16px;
  font-family: {SANS}; font-size: 1rem; line-height: 1.6; color: {TEXT}; background: {BONE};
  border: 1px solid {HAIRLINE}; border-radius: 8px; resize: vertical; }}
textarea:focus {{ outline: none; border-color: {MUTED}; }}
.stats {{ margin-top: 10px; font-size: 0.85rem; color: {MUTED}; }}
.stats b {{ color: {INK}; font-weight: 600; }}
</style></head><body>
<div class="passage" id="target">{escape(passage)}</div>
<textarea id="box" spellcheck="false" autocomplete="off"
  placeholder="Click here and type the paragraph above at your usual pace."></textarea>
<div class="stats" id="stats">Speed and accuracy appear here as you type.</div>
<script>
const target = document.getElementById("target").textContent;
const box = document.getElementById("box");
const stats = document.getElementById("stats");
let started = null;
box.addEventListener("paste", (event) => event.preventDefault());
box.addEventListener("input", () => {{
  if (started === null) started = performance.now();
  const typed = box.value;
  let correct = 0;
  for (let i = 0; i < typed.length && i < target.length; i++) {{
    if (typed[i] === target[i]) correct++;
  }}
  const minutes = (performance.now() - started) / 60000;
  const wpm = minutes > 0 ? Math.round(typed.length / 5 / minutes) : 0;
  const accuracy = typed.length ? Math.round(100 * correct / typed.length) : 100;
  const done = Math.min(100, Math.round(100 * typed.length / target.length));
  stats.innerHTML = "<b>" + wpm + "</b> words per minute, <b>" + accuracy +
    "%</b> accurate, <b>" + done + "%</b> of the paragraph";
}});
</script></body></html>"""


def confidence_meter(confidence: float, threshold: float) -> str:
    confidence = max(0.0, min(1.0, confidence))
    colour = PASTELS["green"][1] if confidence >= threshold else PASTELS["yellow"][1]
    return (
        '<div class="ct-meter">'
        f'<div class="ct-meter-fill" style="width:{confidence * 100:.1f}%;background:{colour}">'
        "</div>"
        f'<div class="ct-meter-mark" style="left:{threshold * 100:.1f}%"></div>'
        "</div>"
        f'<div class="ct-hint">Confidence {confidence:.2f}. '
        f"The line marks the answer threshold, {threshold:.2f}.</div>"
    )
