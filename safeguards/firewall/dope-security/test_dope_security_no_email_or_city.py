"""dope.security endpoint lists never fall back to the user's email or add the city. Synthetic endpoints only."""
import importlib.util
import json
import unittest
from pathlib import Path


def load(name):
    spec = importlib.util.spec_from_file_location("dope_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ENDPOINTS = [{"emailId": "synth.person@example.test", "cityName": "Synthcity", "fallbackMode": True, "agentVersion": "0.0.1"},
             {"deviceName": "DEVICE-A", "emailId": "other.person@example.test", "cityName": "Synthcity", "fallbackMode": True}]


class NoEmailOrCity(unittest.TestCase):
    def test_lists_carry_no_email_or_city(self):
        for name in ["isfallbackmodedisabled", "isfirmwarecurrent"]:
            text = json.dumps(load(name).transform({"data": {"endpoints": ENDPOINTS}}))
            self.assertNotIn("example.test", text, name)
            self.assertNotIn("Synthcity", text, name)
            self.assertIn("unnamed device", text, name)


if __name__ == "__main__":
    unittest.main()
