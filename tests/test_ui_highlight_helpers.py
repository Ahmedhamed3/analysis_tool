from app.ui_highlight import assign_token_color, escape_html, mark_tokens


def test_assign_token_color_is_deterministic():
    palette = ["#111111", "#222222", "#333333"]
    first = assign_token_color("ProcessGuid", palette=palette)
    second = assign_token_color("ProcessGuid", palette=palette)
    other = assign_token_color("TargetFilename", palette=palette)
    assert first == second
    assert first in palette
    assert other in palette


def test_escape_and_mark_tokens():
    text = '<script>alert("x")</script> ProcessGuid=ABC-123'
    token_to_color = {"ProcessGuid": "#fde68a", "ABC-123": "#a7f3d0"}
    result = mark_tokens(text, token_to_color)
    assert "&lt;script&gt;" in result
    assert '<mark class="highlight" style="background: #fde68a;">ProcessGuid</mark>' in result
    assert '<mark class="highlight" style="background: #a7f3d0;">ABC-123</mark>' in result
    assert escape_html(text) != text
