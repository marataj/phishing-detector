#  ---------------------------------------------------------------------------------------------------------------------
# Name:             source.detector.detector
# Created By :      marataj
# Created Date:     2024-11-13
#  ---------------------------------------------------------------------------------------------------------------------

"""
Module containing the logic of detector engine.

"""

import asyncio

import validators
from aiohttp import ClientSession, ClientTimeout

from source.detector.report import Report, SubReport, generate_report
from source.detector.scanners.alive_scanner import AliveScanner
from source.detector.scanners.chrome_safe_browsing_scanner import \
    ChromeSafeBrowsingScanner
from source.detector.scanners.google_safe_browsing_api_scanner import \
    GoogleSafeBrowsingAPIScanner
from source.detector.scanners.scanner import Scanner
from source.detector.scanners.virus_total_scanner import VirusTotalScanner

__all__ = ["Detector"]


class Detector:
    """
    Class responsible for detecting the malicious URLs using several methodes.

    """

    class ValidationError(Exception):
        pass

    def __init__(self, chrome_sb_scanner_enabled: bool = False):
        """
        Initialization of the Detector instance.

        Parameters
        ----------
        chrome_sb_scanner_enabled: bool, default False
            Flag enabling using the GoogleSafeBrowsingScanner. Due to potential damage, the scan must be enabled
            consciously.

        """
        self._supported_scanners = [VirusTotalScanner, GoogleSafeBrowsingAPIScanner, AliveScanner]
        if chrome_sb_scanner_enabled:
            self._supported_scanners.append(ChromeSafeBrowsingScanner)

        self._global_session_timeout = ClientTimeout(10)

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
            if validators.url(url):
                continue
            errors.append(url)

        if len(errors):
            raise self.ValidationError(f"Invalid URLs: {errors}")

        return urls

    async def _scan_urls(self, scanners: list[Scanner]) -> None:
        """
        Asynchronous method which starts scanning using given scanners instances.

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
        return self._create_report(reports, url_list)

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
