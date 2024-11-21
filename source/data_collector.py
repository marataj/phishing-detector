#  ---------------------------------------------------------------------------------------------------------------------
# Name:             source.data_collector
# Created By :      marataj
# Created Date:     2024-11-17
#  ---------------------------------------------------------------------------------------------------------------------

"""
Module related with data collection feature.

"""

import io
from datetime import datetime, timedelta
from http import HTTPStatus
from http.client import HTTPException
from typing import Literal

import pandas as pd
import requests

__all__ = ["DataCollector"]


class DataCollector:
    """
    Class responsible for collecting the reported URLs from supported open sources. Provides current data from supported
    filter lists sources.

    """

    def __init__(self):
        """
        Initialization of the DataCollector instance.

        """
        self._openphish_url = "https://openphish.com/feed.txt"
        self._openphish_urls = None
        self._openphish_last_update = datetime(year=2000, month=1, day=1)
        self._openphish_update_freq = timedelta(hours=12)

        self._phishstats_url = "https://phishstats.info/phish_score.csv"
        self._phishstats_urls = None
        self._phishstats_last_update = datetime(year=2000, month=1, day=1)
        self._phishstats_update_freq = timedelta(minutes=90)

    def get_urls_openphish(self, url_number: int) -> list[str]:
        """
        Method responsible for collecting URLs from the OpenPhishing feed. Once the feed is retrieved it's cacheduntil
        next function call when the update timeout is exceeded.
        https://openphish.com/

        Parameters
        ----------
        url_number: `int`
            Number of URLs to be collected.

        Raises
        ------
        HTTPException
            Raises when response with unexpected code was received.

        Returns
        -------
        `list` [`str`]
            List of URLs.

        """
        if not self._openphish_url or datetime.now() - self._openphish_last_update > self._openphish_update_freq:
            response = requests.get(url=self._openphish_url)
            if response.status_code != HTTPStatus.OK:
                HTTPException(f"Unexpected response code from OpenPhish: {response.status_code}")

            self._openphish_urls = response.text.split("\n")
            self._openphish_last_update = datetime.now()

        return self._openphish_urls[:url_number]

    def get_urls_phishstats(self, url_number: int) -> list[str]:
        """
        Method responsible for collecting URLs from the PhishStats feed. Once the feed is retrieved it's cached until
        next function call when the update timeout is exceeded.
        https://phishstats.info/

        Parameters
        ----------
        url_number: `int`
            Number of URLs to be collected.

        Raises
        ------
        HTTPException
            Raises when response with unexpected code was received.

        Returns
        -------
        `list` [`str`]
            List of URLs.

        """
        if not self._phishstats_urls or datetime.now() - self._phishstats_last_update > self._phishstats_update_freq:
            response = requests.get(url=self._phishstats_url)
            if response.status_code != HTTPStatus.OK:
                HTTPException(f"Unexpected response code from PhishState: {response.status_code}")

            self._phishstats_urls = pd.read_csv(
                io.StringIO(response.text), skiprows=10, names=["Date", "Score", "URL", "IP"]
            ).URL.tolist()
            self._phishstats_last_update = datetime.now()

        return self._phishstats_urls[:url_number]

    def get_urls(self, url_number: int, source: Literal["openphish", "pishstats"] | None = None) -> list[str]:
        """
        Collecting data from both available data sources and returns combined url list.

        Parameters
        ----------
        url_number: `int`
            Number of URLs to be collected.
        source: `Literal` [`str`] | None, default None
            Optional parameter determining source of data. If none, results are collected from all available sources.

        Raises
        ------
        AttributeError
            Raises when source parameter is invalid.

        Returns
        -------
        `list` [`str`]
            List of URLs.

        """
        if source and source not in ["openphish", "pishstats"]:
            raise AttributeError(f"Invalid source: {source}")
        if not source:
            res = [*self.get_urls_openphish(url_number // 2), *self.get_urls_phishstats(url_number - url_number // 2)]
        elif source == "openphish":
            res = self.get_urls_openphish(url_number)
        else:
            res = self.get_urls_phishstats(url_number)

        return res
