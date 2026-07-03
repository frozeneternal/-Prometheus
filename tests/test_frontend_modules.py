from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"


class FrontendModuleTests(unittest.TestCase):
    def test_index_uses_module_entrypoint(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")

        self.assertIn('type="module"', index_html)
        self.assertIn('src="/js/app.js"', index_html)
        self.assertNotIn('src="/app.js"', index_html)

    def test_frontend_base_modules_exist_and_are_imported(self) -> None:
        expected_modules = [
            PUBLIC / "js" / "app.js",
            PUBLIC / "js" / "api.js",
            PUBLIC / "js" / "dom.js",
            PUBLIC / "js" / "format.js",
            PUBLIC / "js" / "state.js",
        ]
        for module_path in expected_modules:
            self.assertTrue(module_path.exists(), f"missing {module_path.relative_to(ROOT)}")

        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        for import_path in ("./api.js", "./dom.js", "./format.js", "./state.js"):
            self.assertIn(import_path, app_js)

    def test_legacy_root_app_script_removed(self) -> None:
        self.assertFalse((PUBLIC / "app.js").exists())

    def test_frontend_modules_keep_utf8_labels(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        format_js = (PUBLIC / "js" / "format.js").read_text(encoding="utf-8")
        state_js = (PUBLIC / "js" / "state.js").read_text(encoding="utf-8")

        for expected in ("\u670d\u52a1\u5668", "\u7c7b\u578b", "\u5730\u5740", "\u5bbf\u4e3b\u673a"):
            self.assertIn(expected, app_js)
        for expected in ("\u5185\u5b58", "\u78c1\u76d8", "\u6b63\u5e38", "\u5df2\u8fc7\u671f"):
            self.assertIn(expected, format_js)
        self.assertIn("\u5168\u90e8", state_js)

        for module_text in (app_js, format_js, state_js):
            for bad_marker in ("\u93c8", "\u934f", "\u95b0", "\ufffd"):
                self.assertNotIn(bad_marker, module_text)


if __name__ == "__main__":
    unittest.main()
