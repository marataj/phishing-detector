#  ---------------------------------------------------------------------------------------------------------------------
# Name:             data_collector
# Created By :      marataj
# Created Date:     2024-11-17
#  ---------------------------------------------------------------------------------------------------------------------

"""
Module related with data collection feature.

"""

import io

import pandas as pd
import requests

__all__ = []


class DataCollector:
    """
    Class responsible for collecting the reported URLs from supported open sources.

    """

    def __init__(self):
        """
        Initialization of the DataCollector instance.

        """
        self._open_phish_url = "https://openphish.com/feed.txt"
        self._phishstats_url = "https://phishstats.info/phish_score.csv"
        self._open_phish_urls = None
        self._phish_stats_urls = None

    def open_phish_get_urls(self, url_number: int) -> list[str]:
        """
        Method responsible for collecting URLs from the OpenPhishing feed. Once the feed is retrieved it's cached.

        Parameters
        ----------
        url_number: `int`
            Number of URLs to be collected.

        Returns
        -------
        `list` [`str`]
            List of URLs.

        """
        if not self._open_phish_url:
            self._open_phish_urls = requests.get(url=self._open_phish_url).text.split("\n")

        return self._open_phish_urls[:url_number]

    def _phishstats_get_urls(self, url_number: int) -> list[str]:
        """
        Method responsible for collecting URLs from the PhishStats feed. Once the feed is retrieved it's cached.

        Parameters
        ----------
        url_number: `int`
            Number of URLs to be collected.

        Returns
        -------
        `list` [`str`]
            List of URLs.

        """
        if self._phish_stats_urls is None:
            r = requests.get(url=self._phishstats_url)
            self._phish_stats_urls = pd.read_csv(
                io.StringIO(r.text), skiprows=10, names=["Date", "Score", "URL", "IP"]
            ).URL.tolist()

        return self._phish_stats_urls[url_number]
