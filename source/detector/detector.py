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

from aiohttp import ClientSession, ClientTimeout

from source.detector.report import Report, SubReport, generate_report
from source.detector.scanners.google_safe_browsing_scanner import GSBScanner
from source.detector.scanners.scanner import Scanner
from source.detector.scanners.virus_total_scanner import VirusTotalScanner
from source.detector.scanners.website_status_scanner import \
    WebsiteStatusScanner

__all__ = ["Detector"]


class Detector:
    """
    Class responsible for detecting the malicious URLs using several methodes.

    """

    class ValidationError(Exception):
        pass

    def __init__(self):
        """
        Initialization of the Detector instance.

        """
        self._supported_scanners = [VirusTotalScanner, GSBScanner, WebsiteStatusScanner]
        self._global_session_timeout = ClientTimeout(5)

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
        async with ClientSession(timeout=self._global_session_timeout) as session:
            await asyncio.gather(*[scanner.run(session) for scanner in scanners])

    def scan(self, url_list: list[str]) -> Report:
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
    def _create_report(sub_reports: list[SubReport], urls: list[str]) -> Report:
        """
        Method responsible for creating the final report.

        Parameters
        ----------
        sub_reports: `list` [`SubReport`]
            List containing sub-reports from each scanner.
        urls: `list` [`str`]
            List containing scanned URLs.

        Returns
        -------
        `Report`
            Final report from URL scanning.

        """
        return generate_report(sub_reports, urls)
