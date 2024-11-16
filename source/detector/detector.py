#  ---------------------------------------------------------------------------------------------------------------------
# Name:             detector.detector
# Created By :      marataj
# Created Date:     2024-11-13
#  ---------------------------------------------------------------------------------------------------------------------

"""
Module containing the logic of detector engine.

"""

import asyncio
from urllib.parse import urlparse

from aiohttp import ClientSession

from source.detector.scanners.google_safe_browsing_scanner import GSBScanner
from source.detector.scanners.scanner import Scanner
from source.detector.scanners.virus_total_scanner import VirusTotalScanner
from source.detector.scanners.website_status_scanner import WebsiteStatusScanner

__all__ = ["Detector"]


class Detector:
    """
    Class responsible for detecting the malicious URLs using several methodes.
    TODO: processing of the final report, overall scan duration in stats

    """

    class ValidationError(Exception):
        pass

    def __init__(self):
        """
        Initialization of the Detector instance.

        """
        self._supported_scanners = [VirusTotalScanner, GSBScanner, WebsiteStatusScanner]
        self._global_session_timeout_s = 5

    def _validate_input(self, urls: list[str]) -> list[str]:
        """
        Method responsible for validation of the URLs to be scanned.

        Parameters
        ----------
        urls: `list` [`str`]
            List of URLs to be validated.

        Raises
        ------
        ValidationError
            Raises if any from given URLs is not valid.

        Returns
        -------
        `list` [`str`]
            Validated URLs.

        """
        errors = []
        for url in urls:
            if self._validate_url(url):
                continue
            errors.append(url)

        if len(errors):
            raise self.ValidationError(f"Invalid URLs: {errors}")

        return urls

    async def _scan_urls(self, scanners: list[Scanner]) -> None:
        """
        Asynchronous methode which starts scanning using given scanners instances.

        Parameters
        ----------
        scanners: `list` [`Scanner`]
            Lst of scanners.

        """
        async with ClientSession(timeout=self._global_session_timeout_s) as session:
            await asyncio.gather(*[scanner.run(session) for scanner in scanners])

    def scan(self, url_list: list[str]) -> dict:
        self._validate_input(url_list)
        scanners = [scannerType(url_list) for scannerType in self._supported_scanners]
        asyncio.run(self._scan_urls(scanners))

        reports = [scanner.generate_report() for scanner in scanners]
        print(reports)
        return self._create_report(reports, url_list)

    @staticmethod
    def _validate_url(url: str) -> bool:
        """
        Method responsible for validation of the single URL.

        Parameters
        ----------
        url: `str`
            URL to be validated.

        Returns
        -------
        `bool`
            True if URL is valid, False oterwise.

        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except AttributeError:
            return False

    @staticmethod
    def _create_report(input_reports, urls) -> dict:
        # TODO: add main is_phising result
        report = {"results": {url: {} for url in urls}, "stats": {}}
        for i in input_reports:
            for url in urls:
                report["results"][url].update({**i["results"][url]})
            report["stats"].update(i["stats"])

        return report
