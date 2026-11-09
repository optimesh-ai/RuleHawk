"""The citation registry, loaded from its file without importing the
engine package."""
from __future__ import annotations

import importlib.util
import os
import sys

_NAME = "rulehawk_check._registry"
_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "rulehawk", "citations.py")


def registry():
    """The loaded citations module (once per process)."""
    mod = sys.modules.get(_NAME)
    if mod is None:
        spec = importlib.util.spec_from_file_location(_NAME, _PATH)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[_NAME] = mod          # dataclasses look the module up
        try:
            spec.loader.exec_module(mod)
        except BaseException:
            sys.modules.pop(_NAME, None)
            raise
    return mod
