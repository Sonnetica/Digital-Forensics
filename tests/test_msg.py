"""Outlook MSG parsing: real fixtures, HTML code pages and RTF-encapsulated bodies."""

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from etrace.parser import codepage_codec, decode_msg_html, parse_email  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "msg"
HAS_EXTRACT_MSG = importlib.util.find_spec("extract_msg") is not None


class MsgHtmlDecodingTests(unittest.TestCase):
    PAGE = '<p>Café invoice: <a href="https://portal.vendor.example/résumé">view</a></p>'

    def test_declared_code_page_is_used(self):
        text, codec, basis, problem = decode_msg_html(self.PAGE.encode("cp1252"), 1252)
        self.assertIn("résumé", text)
        self.assertEqual((codec, basis, problem), ("cp1252", "PidTagInternetCodepage 1252", None))

    def test_code_page_table_covers_common_outlook_values(self):
        for codepage, expected in ((65001, "utf-8"), (936, "gbk"), (20127, "ascii"), (28591, "iso8859-1"), (50220, "iso2022_jp"), (1251, "cp1251")):
            with self.subTest(codepage=codepage):
                self.assertEqual(codepage_codec(codepage), expected)
        self.assertIsNone(codepage_codec(None))
        self.assertIsNone(codepage_codec(99999))

    def test_meta_charset_then_utf8_when_no_code_page(self):
        page = '<meta http-equiv="Content-Type" content="text/html; charset=gb2312">发票'
        text, codec, basis, problem = decode_msg_html(page.encode("gb2312"), None)
        self.assertIn("发票", text)
        self.assertEqual((codec, basis, problem), ("gb2312", "HTML meta charset", None))
        text, codec, basis, _ = decode_msg_html(self.PAGE.encode("utf-8"), None)
        self.assertEqual((codec, basis), ("utf-8", "UTF-8 default"))

    def test_bytes_that_contradict_the_code_page_are_flagged(self):
        text, codec, _, problem = decode_msg_html(self.PAGE.encode("cp1252"), 65001)
        self.assertEqual(codec, "cp1252")
        self.assertIn("r\u00e9sum\u00e9", text)  # last-resort Windows-1252 decode
        self.assertIn("Windows-1252", problem)
        text, codec, basis, problem = decode_msg_html(self.PAGE.encode("utf-8"), 20127)
        self.assertEqual((codec, basis), ("utf-8", "UTF-8 default"))
        self.assertIn("not valid ascii", problem)


@unittest.skipUnless(HAS_EXTRACT_MSG, "extract-msg is not installed (pip install -e .)")
class RealMsgFixtureTests(unittest.TestCase):
    def parse(self, name):
        return parse_email((FIXTURES / name).read_bytes(), name)

    def test_html_is_reconstructed_from_compressed_rtf(self):
        for name in ("other.msg", "outer.msg"):
            with self.subTest(name=name):
                record = self.parse(name)
                derived = [p for p in record["parts"] if p.get("derived_from")]
                self.assertEqual(len(derived), 1)
                self.assertEqual(derived[0]["content_type"], "text/html")
                self.assertTrue(derived[0]["location"].endswith(":encapsulated-html"))
                self.assertIn("msg_body_from_rtf", {w["code"] for w in record["warnings"]})
                self.assertNotIn("unsupported_msg_body", {w["code"] for w in record["warnings"]})

    def test_non_utf8_code_page_text_is_readable(self):
        record = self.parse("other.msg")  # PidTagInternetCodepage 936 (GBK)
        self.assertIn("这是服务器", record["body_preview"])
        self.assertNotIn("charset_fallback", {w["code"] for w in record["warnings"]})

    def test_embedded_items_and_missing_transport_headers_are_reported(self):
        record = self.parse("outer.msg")
        codes = {w["code"] for w in record["warnings"]}
        self.assertTrue({"synthesized_headers", "embedded_msg_item", "missing_date"} <= codes)
        self.assertEqual(record["format"], "msg")


class MissingExtractMsgTests(unittest.TestCase):
    def test_clear_error_when_extract_msg_is_absent(self):
        raw = (FIXTURES / "outer.msg").read_bytes()
        with mock.patch.dict(sys.modules, {"extract_msg": None, "extract_msg.exceptions": None}):
            with self.assertRaisesRegex(ValueError, "needs the extract-msg package"):
                parse_email(raw, "outer.msg")


if __name__ == "__main__":
    unittest.main()
