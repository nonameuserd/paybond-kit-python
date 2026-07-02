from __future__ import annotations

from collections.abc import Generator

import pytest

from paybond_kit.dev.trace_buffer import clear_dev_trace_events


@pytest.fixture(autouse=True)
def _isolated_dev_trace_buffer() -> Generator[None, None, None]:
    clear_dev_trace_events()
    yield
    clear_dev_trace_events()
