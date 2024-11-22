#  ---------------------------------------------------------------------------------------------------------------------
# Name:             test.unit_tests.source.detector.test_detector
# Created By :      marataj
# Created Date:     2024-11-22
#  ---------------------------------------------------------------------------------------------------------------------

"""
Unit tests of the detector module.

"""

from unittest.mock import patch

import pytest

from source.detector.detector import Detector


@pytest.mark.parametrize(
    "urls",
    [
        [1, 2, 3, 4],
        ["url1", "url2"],
        ["https://valid.com", "http:/invalid.com"],
        ["https://valid.com", "http://valid.com", "hppp://invalid.pl"],
    ],
)
def test_validate_input_invalid(urls):
    d = Detector()
    with pytest.raises(Detector.ValidationError):
        d._validate_input(urls)


@pytest.fixture()
def mock_virustotal():
    with patch("source.detector.detector.VirusTotalScanner", autospec=True) as mock_virustotal:
        mock_virustotal_instance = mock_virustotal.return_value
        yield mock_virustotal_instance


@pytest.fixture()
def mock_safebrowsing_api():
    with patch("source.detector.detector.GoogleSafeBrowsingAPIScanner", autospec=True) as mock_safebrowsing_api:
        mock_safebrowsing_api_instance = mock_safebrowsing_api.return_value
        yield mock_safebrowsing_api_instance


@pytest.fixture()
def mock_alive():
    with patch("source.detector.detector.AliveScanner", autospec=True) as mock_alive:
        mock_alive_instance = mock_alive.return_value
        yield mock_alive_instance


@pytest.fixture()
def mock_chrome():
    with patch("source.detector.detector.ChromeSafeBrowsingScanner", autospec=True) as mock_chrome:
        mock_chrome_instance = mock_chrome.return_value
        yield mock_chrome_instance


@patch("source.detector.detector.Detector._create_report")
def test_scan_without_chrome(mock_create_report, mock_virustotal, mock_safebrowsing_api, mock_alive, mock_chrome):
    d = Detector()
    d.scan(["https://valid.com", "http://valid.com"])

    for mock in [mock_virustotal, mock_safebrowsing_api, mock_alive]:
        mock.run.assert_awaited_once()

    mock_chrome.run.assert_not_awaited()


@patch("source.detector.detector.Detector._create_report")
def test_scan_with_chrome(mock_create_report, mock_virustotal, mock_safebrowsing_api, mock_alive, mock_chrome):
    d = Detector(True)
    d.scan(["https://valid.com", "http://valid.com"])

    for mock in [mock_virustotal, mock_safebrowsing_api, mock_alive, mock_chrome]:
        mock.run.assert_awaited_once()
