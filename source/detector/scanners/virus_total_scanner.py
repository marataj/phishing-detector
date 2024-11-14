#  ---------------------------------------------------------------------------------------------------------------------
# Name:             detector.scanners.virus_total_scanner
# Created By :      marataj
# Created Date:     2024-11-13
#  ---------------------------------------------------------------------------------------------------------------------

"""
Module containing implementation of the VirusTotal scanner.

"""

import asyncio
from collections import namedtuple
from datetime import datetime
from http import HTTPStatus
from http.client import HTTPException
from typing import Any

from aiohttp import ClientSession

from source.detector.scanners.scanner import Scanner
from source.settings import VIRUS_TOTAL_API_KEY

__all__ = []


class VirusTotalScanner(Scanner):
    """
    Class responsible for scanning the URLs with using VirusTotal API.

    """

    URLScanID = namedtuple("URLScanID", "url, id")
    URLScanResult = namedtuple("URLScanResult", "url, result")

    def __init__(self, url_list: list[str]) -> None:
        """
        Initializes the scanner instance.

        Parameters
        ----------
        url_list : `list` [`str`]
            List of the URLs to be scanned.

        """
        super().__init__(url_list)
        self._api_key = VIRUS_TOTAL_API_KEY
        self._api_url = "https://www.virustotal.com/api/v3/"
        self._retry_counter = 5
        self._results: list[VirusTotalScanner.URLScanResult] | None = None
        self._scan_time = None

    async def _scan_single_url(self, session: ClientSession, url: str) -> URLScanID:
        """
        Asynchronous method sending scan request for single URL.

        Parameters
        ----------
        session : `ClientSession`
            AioHTTP session for asynchronous HTTP requests.
        url : `str`
            URL to be scanned.

        Raises
        ------
        `HTTPException`
            Raised after unexpected status of API response.

        Returns
        -------
        `URLScanID`
            Object containing url and ID of the scann

        """
        async with session.post(
            url=f"{self._api_url}urls",
            headers={"x-apikey": self._api_key},
            data={"url": url},
        ) as response:
            if response.status != HTTPStatus.OK:
                raise HTTPException(
                    f"Unexpected response status: {HTTPStatus(response.status)}"
                )

            body = await response.json()
            return self.URLScanID(url, body["data"]["id"])

    async def _scan_urls(self, session: ClientSession) -> list[URLScanID]:
        """
        Method responsible for sending asynchronous scan requests for URLs.

        Parameters
        ----------
        session : `ClientSession`
            AioHTTP session for asynchronous HTTP requests.

        Returns
        -------
        `list` [`URLScanID`]
            List of IDs of scans on the API side.

        """
        tasks = [self._scan_single_url(session, url) for url in self.url_list]
        return await asyncio.gather(*tasks)

    async def _get_single_result(
        self, session: ClientSession, scann_id: URLScanID
    ) -> URLScanResult:
        """
        Method sending get result request for single URL.

        Parameters
        ----------
        session : `ClientSession`
            AioHTTP session for asynchronous HTTP requests.
        scann_id : `URLScanID`
            Object containing URL and ID of the scann corresponding to the requested analysis results.

        Raises
        ------
        `HTTPException`
            Raises after unexpected status of the API response.
        `ValueError`
            Raises after exceeding the maximum number of attempts of get requests.

        Returns
        -------
        `URLScanResult`
            Object containing scanned URL and scanning result respectively.

        """
        for _ in range(self._retry_counter):
            async with session.get(
                url=f"{self._api_url}analyses/{scann_id.id}",
                headers={"x-apikey": self._api_key},
            ) as response:
                if response.status != HTTPStatus.OK:
                    raise HTTPException(
                        f"Unexpected response status of VirusTotal response: {HTTPStatus(response.status)}"
                    )
                #  TODO: is there a better way to check if the analysis is ready ? (like dedicated endpoint)
                body = await response.json()
                if body["data"]["attributes"]["status"] == "completed":
                    is_phishing = int(body["data"]["attributes"]["stats"]["malicious"]) >= 3
                    return self.URLScanResult(scann_id.url, is_phishing)

                await asyncio.sleep(0.1)

            raise ValueError(
                "Maximum number of attempts to get the TotalVirus scan result exceeded."
            )

    async def _get_results(
        self, session: ClientSession, scan_ids: list[URLScanID]
    ) -> list[URLScanResult]:
        """
        Method responsible for sending asynchronous requests in order to retrieving results from URL scanning.

        Parameters
        ----------
        session : `ClientSession`
            AioHTTP session for asynchronous HTTP requests.

        scan_ids : `list` [`URLScanID`]
            List with `URLScanID` objects, that contain the URL and ID of the scan on the API side.

        Returns
        -------
        `list` [`URLScanResult`]
            List with `URLScanResult` objects, that contain the URL and the result from its scan.

        """
        tasks = [self._get_single_result(session, scan_id) for scan_id in scan_ids]
        return await asyncio.gather(*tasks)

    async def run(self, session: ClientSession) -> None:
        """
        Method that runs the scan of the URLs.

        Parameters
        ----------
        session : `ClientSession`
            Session for execution of asynchronous HTTP requests.

        """
        start_time = datetime.now()
        scan_ids = await self._scan_urls(session)
        self._results = await self._get_results(session, scan_ids)
        self._scan_time = datetime.now() - start_time

    def generate_report(self) -> dict[str, Any] | None:
        if self._results is None:
            return None

        return {
            "results": {
                url_scan_result.url: {"is_phishing_VirusTotal": url_scan_result.result}
                for url_scan_result in self._results
            },
            "stats": {"scan_time_VirusTotal": self._scan_time},
        }
