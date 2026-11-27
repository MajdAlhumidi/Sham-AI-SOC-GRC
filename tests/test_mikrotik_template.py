import re
import unittest
from pathlib import Path
from xml.etree import ElementTree


CONFIG = Path(__file__).resolve().parents[1] / "configs" / "wazuh"


class MikroTikTemplateTests(unittest.TestCase):
    def test_canonical_and_previous_names_use_the_native_rule(self):
        decoder = ElementTree.parse(CONFIG / "mikrotik_native_decoder.xml").getroot()
        topics = "system,error,critical"
        message = "login failure for user review-user from 192.0.2.17 via winbox"
        for name in ("MikroTik", "MOKROTIK-STAR"):
            with self.subTest(name=name):
                log = f"{topics} {name}: {message}"
                self.assertIsNotNone(re.search(decoder.findtext("prematch"), log))
                matches = re.search(decoder.findtext("regex"), log).groups()
                self.assertEqual(dict(zip(decoder.findtext("order").split(","), matches)), {
                    "dstuser": "review-user", "srcip": "192.0.2.17", "protocol": "winbox",
                })
        for log in (f"{topics} MikroTik-OTHER: {message}", f"{topics} OtherRouter: {message}",
                    "system,info MikroTik: link up on ether1"):
            self.assertIsNone(re.search(decoder.findtext("prematch"), log))
        rules = ElementTree.parse(CONFIG / "mikrotik_native_rules.xml").getroot()
        self.assertEqual(rules.find("./rule[@id='100110']/decoded_as").text, decoder.get("name"))
        self.assertEqual(rules.find("./rule[@id='100111']").get("level"), "7")
        self.assertEqual(rules.find("./rule[@id='100111']/if_sid").text, "100110")
