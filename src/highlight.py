"""Turn the matched spans of a message into safe, highlighted HTML."""

from __future__ import annotations

import html
import re


def merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[list[int]] = []
    for start, end in sorted(s for s in spans if s[1] > s[0]):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(s, e) for s, e in merged]


def highlight_html(text: str, spans: list[tuple[int, int]]) -> str:
    """Return HTML with every span wrapped in <mark>. All text is escaped."""
    out, pos = [], 0
    for start, end in merge_spans(spans):
        out.append(html.escape(text[pos:start]))
        out.append(f"<mark>{html.escape(text[start:end])}</mark>")
        pos = end
    out.append(html.escape(text[pos:]))
    # every kind of line ending becomes <br>, so the result is one single line
    return re.sub(r"\r\n|\r|\n", "<br>", "".join(out))
