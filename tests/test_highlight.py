from src.highlight import highlight_html, merge_spans


def test_merge_overlapping_and_adjacent_spans():
    assert merge_spans([(5, 8), (0, 3), (2, 4), (8, 10)]) == [(0, 4), (5, 10)]


def test_empty_spans_are_ignored():
    assert merge_spans([(3, 3)]) == []


def test_highlight_wraps_spans():
    assert highlight_html("click here now", [(6, 10)]) == "click <mark>here</mark> now"


def test_html_in_message_is_escaped():
    text = "<script>alert(1)</script> win"
    start = text.index("win")
    out = highlight_html(text, [(start, start + 3)])
    assert "<script>" not in out
    assert "&lt;script&gt;" in out
    assert out.endswith("<mark>win</mark>")


def test_newlines_become_line_breaks():
    assert highlight_html("a\nb", []) == "a<br>b"


def test_every_kind_of_line_ending_becomes_a_line_break():
    # a blank line would end an HTML block and let Markdown run on the rest
    out = highlight_html("a\r\n\r\nb\rc\n\nd", [])
    assert out == "a<br><br>b<br>c<br><br>d"
    assert "\n" not in out and "\r" not in out
