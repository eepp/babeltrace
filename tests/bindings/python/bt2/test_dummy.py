# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 EfficiOS Inc.

# This file only exists during the transition from `unittest` to pytest
# to make sure there's at least one remaining test when everything is
# converted to pytest.

import unittest


class MeowTestCase(unittest.TestCase):
    def test_meow(self):
        pass
