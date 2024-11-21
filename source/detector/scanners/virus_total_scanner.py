#  ---------------------------------------------------------------------------------------------------------------------
# Name:             source.detector.scanners.virus_total_scanner
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

from aiohttp import ClientSession

from source.detector.report import IsPhishingResult, ScanTime, SubReport
from source.detector.scanners.scanner import Scanner
from source.settings import VIRUS_TOTAL_API_KEY

__all__ = ["VirusTotalScanner"]


class VirusTotalApiError(Exception):
    """
    Exception represents API errors.

    """
    pass


class VirusTotalScanner(Scanner):
    """
    Class responsible for scanning the URLs with using VirusTotal API.

    """
    URLScanID = namedtuple("URLScanID", "url, id")
    URLScanResult = namedtuple("URLScanResult", "url, result")

    def __init__(self, url_list: list[str]) -> None:
        """
        Initializes the scanner instance.

        Raises
        ------
        AttributeError
            Raises when lack of API key detected.

        Parameters
        ----------
        url_list : `list` [`str`]
            List of the URLs to be scanned.

        """
        super().__init__(url_list)
        self.__api_key = VIRUS_TOTAL_API_KEY
        if not self.__api_key:
            raise AttributeError("Lack of VirusTotal API KEY.")
        self._api_url = "https://www.virustotal.com/api/v3/"
        self._retry_counter = 5
        self._retry_delay_s = 20
        self._results: dict[str, IsPhishingResult] | None = None
        self._scan_time: ScanTime | None = None
        self._phishing_threshold = 3

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
        HTTPException
            Raises after unexpected status of API response.
        VirusTotalAPIException
            Raises when number of request was exceeded.
        Returns
        -------
        `URLScanID`
            Object containing url and ID of the scann

        """
        async with session.post(
            url=f"{self._api_url}urls", headers={"x-apikey": self.__api_key}, data={"url": url}
        ) as response:
            if response.status != HTTPStatus.OK:
                raise HTTPException(f"VirusTotal: Unexpected response status: {HTTPStatus(response.status)}")
            if response.status == HTTPStatus.TOO_MANY_REQUESTS:
                raise VirusTotalApiError("Number of requests per account was exceeded. Check VirusTotal account.")

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

    async def _get_single_result(self, session: ClientSession, scann_id: URLScanID) -> URLScanResult:
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
        HTTPException
            Raises after unexpected status of the API response.
        ValueError
            Raises after exceeding the maximum number of attempts of get requests.
        VirusTotalAPIException
            Raises when number of request was exceeded.

        Returns
        -------
        `URLScanResult`
            Object containing scanned URL and scanning result respectively.

        """
        # TODO: This method is too complex - must be split and simplified
        for _ in range(self._retry_counter):
            async with session.get(
                url=f"{self._api_url}analyses/{scann_id.id}", headers={"x-apikey": self.__api_key}
            ) as response:
                if response.status != HTTPStatus.OK:
                    raise HTTPException(
                        f"Unexpected response status of VirusTotal response: {HTTPStatus(response.status)}"
                    )
                if response.status == HTTPStatus.TOO_MANY_REQUESTS:
                    raise VirusTotalApiError("Number of requests per account was exceeded. Check VirusTotal account.")

                body = await response.json()

                if body["data"]["attributes"]["status"] == "completed":
                    malicious_num = int(body["data"]["attributes"]["stats"]["malicious"])
                    return self.URLScanResult(scann_id.url, self._eval_is_phishing(malicious_num))

                await asyncio.sleep(self._retry_delay_s)

        raise ValueError("Maximum number of attempts to get the TotalVirus scan result exceeded.")

    async def _get_results(self, session: ClientSession, scan_ids: list[URLScanID]) -> list[URLScanResult]:
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

    def _eval_is_phishing(self, malicious_num: int) -> bool:
        """
        Utility function responsible for evaluation if the URL shall be considered as phishing.

        Parameters
        ----------
        malicious_num : `int`
            Number of reports defining the URL as malicious.

        Returns
        -------
        `bool`
            True if the URL shall be considered as phishing, False otherwise.

        """
        return malicious_num >= self._phishing_threshold

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
        results = await self._get_results(session, scan_ids)
        self._results = {res.url: IsPhishingResult(self.__class__.__name__, res.result) for res in results}
        self._scan_time = ScanTime(self.__class__.__name__, datetime.now() - start_time)

    def generate_report(self) -> SubReport:
        """
        Method responsible for generating the SubReport from the VirusTotal scan.

        Raises
        ------
        ValueError
            Raises when there is no results to be processed.

        Returns
        -------
        `SubReport`
            SubReport from the VirusTotal scan.

        """
        if not (self._results and self._scan_time):
            raise ValueError("Report generating suspended - lack of results to be processed.")
        return SubReport(self.__class__.__name__, self._results, [self._scan_time])
