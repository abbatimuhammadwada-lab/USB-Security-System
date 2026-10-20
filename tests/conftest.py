"""
Pytest configuration shared across all test modules.

Forces the Qt "offscreen" platform plugin so the GUI test suite (Phase 4
onward) runs headlessly - no real display required, works in CI and in
this development sandbox alike.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
