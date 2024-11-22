#  ---------------------------------------------------------------------------------------------------------------------
# Name:             test.unit_tests.source.test_data_collector
# Created By :      marataj
# Created Date:     2024-11-21
#  ---------------------------------------------------------------------------------------------------------------------

"""
Unit tests of data_source module.

"""

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from source.data_collector import DataCollector


@pytest.fixture(scope="module")
def openphish_text():
    return "\n".join(["https://dummy.openphish.com"] * 50)


@pytest.fixture(scope="module")
def phishstats_text():
    text = """######################################################################################
    # PhishScore | PhishStats                                                            #
    # Score ranges: 0-2 likely 2-4 suspicious 4-6 phishing 6-10 omg phishing!            #
    # Ranges may be adjusted without notice. List updated every 90 minutes. Do not crawl #
    # too much at the risk of being blocked.                                             #
    # Many Phishing websites are legitimate websites that have been hacked, so keep that #
    # in mind before blocking everything. Feed is provided as is, without any warrant.   #
    # CSV: Date,Score,URL,IP                                                             #
    ######################################################################################
    
    """ + "\n".join(['"2024-11-21 08:01:37","5.80","https://dummy.phishstats.com","1.2.3.4"'] * 50)
    return text


@pytest.mark.parametrize(
    "url_number, exp_response",
    [
        (1, ["https://dummy.openphish.com"]),
        (5, ["https://dummy.openphish.com"] * 5),
        (20, ["https://dummy.openphish.com"] * 20),
    ],
)
def test_get_urls_openphish_resp(requests_mock, openphish_text, url_number, exp_response):
    d = DataCollector()
    requests_mock.get(d._openphish_url, text=openphish_text)

    assert d.get_urls_openphish(url_number) == exp_response


@pytest.mark.parametrize(
    "since_update, get_called",
    [
        (timedelta(minutes=5), False),
        (timedelta(hours=10), False),
        (timedelta(hours=15), True),
    ],
)
def test_get_urls_openphish_return_from_cache(requests_mock, openphish_text, since_update, get_called):
    d = DataCollector()
    d._openphish_urls = ["https://dummy.openphish.com"] * 50
    d._openphish_last_update = datetime.now() - since_update

    requests_mock.get(d._openphish_url, text=openphish_text)
    with patch("source.data_collector.requests.get") as get:
        d.get_urls_openphish(1)

        if get_called:
            get.assert_called()
        else:
            get.assert_not_called()


@pytest.mark.parametrize(
    "url_number, exp_response",
    [
        (1, ["https://dummy.phishstats.com"]),
        (5, ["https://dummy.phishstats.com"] * 5),
        (20, ["https://dummy.phishstats.com"] * 20),
    ],
)
def test_get_urls_phishstats_resp(requests_mock, phishstats_text, url_number, exp_response):
    d = DataCollector()
    requests_mock.get(d._phishstats_url, text=phishstats_text)

    assert d.get_urls_phishstats(url_number) == exp_response


@pytest.mark.parametrize(
    "since_update, read_csv_called",
    [
        (timedelta(minutes=5), False),
        (timedelta(minutes=89), False),
        (timedelta(minutes=100), True),
    ],
)
def test_get_urls_phishstats_return_from_cache(requests_mock, phishstats_text, since_update, read_csv_called):
    d = DataCollector()
    d._phishstats_urls = ["https://dummy.phishstats.com"] * 50
    d._phishstats_last_update = datetime.now() - since_update

    requests_mock.get(d._phishstats_url, text=phishstats_text)
    with patch("source.data_collector.pd.read_csv") as read_csv:
        d.get_urls_phishstats(1)

        if read_csv_called:
            read_csv.assert_called()
        else:
            read_csv.assert_not_called()


@pytest.mark.parametrize(
    "total_num, exp_openpish_num, exp_phishstats_num",
    [
        (49, 24, 25),
        (40, 20, 20),
        (1, 0, 1),
        (2, 1, 1),
        (21, 10, 11),
    ],
)
def test_get_urls(total_num, exp_openpish_num, exp_phishstats_num, requests_mock, phishstats_text, openphish_text):
    d = DataCollector()
    requests_mock.get(d._phishstats_url, text=phishstats_text)
    requests_mock.get(d._openphish_url, text=openphish_text)

    urls = d.get_urls(total_num)

    assert urls.count("https://dummy.openphish.com") == exp_openpish_num
    assert urls.count("https://dummy.phishstats.com") == exp_phishstats_num
