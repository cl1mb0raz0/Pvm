from django.test import SimpleTestCase

from .debversion import compare, is_valid, sort_key


class CompareTests(SimpleTestCase):
    def assertOrdered(self, lower, higher):
        self.assertLess(compare(lower, higher), 0, f"{lower} < {higher}")
        self.assertGreater(compare(higher, lower), 0, f"{higher} > {lower}")

    def test_ubuntu_revisions_compare_numerically(self):
        self.assertOrdered("2.4.41-4ubuntu3.9", "2.4.41-4ubuntu3.17")
        self.assertOrdered("1:8.2p1-4ubuntu0.5", "1:8.2p1-4ubuntu0.10")

    def test_epoch_wins(self):
        self.assertOrdered("9.9", "1:1.0")
        self.assertOrdered("1:9.6p1-3ubuntu13.3", "2:1.0")

    def test_tilde_sorts_before_everything(self):
        self.assertOrdered("1.0~rc1", "1.0")
        self.assertOrdered("1.2.3~ubuntu0.20.04.1", "1.2.3")
        self.assertOrdered("1.0~~", "1.0~")

    def test_esm_and_plus_suffixes_are_newer(self):
        self.assertOrdered("1:7.6p1-4ubuntu0.7", "1:7.6p1-4ubuntu0.7+esm3")
        self.assertOrdered("1.0", "1.0+b1")

    def test_letters_before_symbols(self):
        self.assertOrdered("1.0a", "1.0+")

    def test_equal(self):
        self.assertEqual(compare("1:2.4.41-4ubuntu3.17", "1:2.4.41-4ubuntu3.17"), 0)
        self.assertEqual(compare("2.0", "0:2.0"), 0)
        self.assertEqual(compare("1.001", "1.1"), 0)

    def test_sorting(self):
        versions = ["1.0", "1.0~rc1", "1:0.5", "1.0-1", "1.0+dfsg-1", "0.9"]
        self.assertEqual(sorted(versions, key=sort_key), ["0.9", "1.0~rc1", "1.0", "1.0-1", "1.0+dfsg-1", "1:0.5"])

    def test_validity(self):
        for good in ["2.4.41-4ubuntu3.17", "1:8.2p1-4ubuntu0.5", "5:6.0.16-1ubuntu1", "1.0~rc1"]:
            self.assertTrue(is_valid(good), good)
        for bad in ["", "latest", "v2.4", "2.4 41"]:
            self.assertFalse(is_valid(bad), bad)
