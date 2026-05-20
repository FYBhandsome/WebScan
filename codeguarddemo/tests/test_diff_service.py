from services.diff_service import generate_diff


class TestDiffService:
    def test_generate_diff_returns_text(self):
        original = "x = 1  \n\ny = 2"
        standard = "x = 1\ny = 2"
        diff_text, diff_html = generate_diff(original, standard)
        assert isinstance(diff_text, str)
        assert isinstance(diff_html, str)

    def test_generate_diff_html_contains_table(self):
        diff_text, diff_html = generate_diff("a", "b")
        assert "<table" in diff_html.lower()

    def test_generate_diff_no_change(self):
        code = "x = 1\ny = 2"
        diff_text, diff_html = generate_diff(code, code)
        assert isinstance(diff_text, str)
        assert isinstance(diff_html, str)

    def test_generate_diff_with_difference(self):
        original = "x = 1\ny = 2\nz = 3"
        standard = "x = 1\ny = 2"
        diff_text, diff_html = generate_diff(original, standard)
        assert len(diff_text) > 0

    def test_generate_diff_empty_input(self):
        diff_text, diff_html = generate_diff("", "")
        assert isinstance(diff_text, str)
        assert isinstance(diff_html, str)
