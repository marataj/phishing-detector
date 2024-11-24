#  ---------------------------------------------------------------------------------------------------------------------
# Name:             test.unit_tests.source.detector.scanners.test_alive_scanner
# Created By :      marataj
# Created Date:     2024-11-24
#  ---------------------------------------------------------------------------------------------------------------------

"""
Unit tests of the alive_scanner module.

"""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from source.detector.report import (AliveStats, IsAliveResult, ScanTime,
                                    SubReport)
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


@pytest.mark.asyncio
@patch("aiohttp.ClientSession")
async def test_run(client_session_mock):
    mocked_status = 299
    session = MagicMock()
    session.get.return_value.__aenter__.return_value = SimpleNamespace(status=mocked_status)

    client_session_mock.return_value.__aenter__.return_value = session

    scanner = AliveScanner(["https://mock.com"] * 10)
    await scanner.run(session)

    assert isinstance(scanner._scan_time, ScanTime)
    assert scanner._results == [IsAliveResult(True, mocked_status)] * 10


def test_generate_report():
    scanner = AliveScanner([MagicMock()] * 10)
    scanner._results = [IsAliveResult(True, 200)] * 10
    scanner._scan_time = ScanTime("AliveScanner", timedelta(seconds=1))

    assert scanner.generate_report() == SubReport(
        "AliveScanner",
        [IsAliveResult(True, 200)] * 10,
        [ScanTime("AliveScanner", timedelta(seconds=1)), AliveStats(10, 100)],
    )
