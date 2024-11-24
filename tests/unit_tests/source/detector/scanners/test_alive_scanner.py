#  ---------------------------------------------------------------------------------------------------------------------
# Name:             test.unit_tests.source.detector.scanners.test_alive_scanner
# Created By :      marataj
# Created Date:     2024-11-24
#  ---------------------------------------------------------------------------------------------------------------------

"""
Unit tests of the alive_scanner module.

"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from source.detector.report import IsAliveResult
from source.detector.scanners.alive_scanner import AliveScanner


@pytest.mark.parametrize(
    "code, exp_result",
    [
        (200, True),
        (202, True),
        (400, False),
        (401, False),
        (405, False),
        (500, False),
        (501, False),
        (503, False),
    ],
)
@pytest.mark.asyncio
@patch("aiohttp.ClientSession")
async def test_scan_url_eval(client_session_mock, code, exp_result):
    session = MagicMock()
    session.get.return_value.__aenter__.return_value = SimpleNamespace(status=code)

    client_session_mock.return_value.__aenter__.return_value = session

    scanner = AliveScanner(MagicMock())
    res = await scanner._scan_url(session, "https://url1.com")

    assert res == IsAliveResult(exp_result, code)
