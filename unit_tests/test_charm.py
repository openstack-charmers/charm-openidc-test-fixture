# Copyright 2022 ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import sys
import unittest

from ops.testing import Harness

sys.path.append('src')  # noqa

from charm import CharmOpenidcTestFixtureCharm


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(CharmOpenidcTestFixtureCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_on_install(self):
        """Test install hook."""
        pass
