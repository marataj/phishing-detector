#  ---------------------------------------------------------------------------------------------------------------------
# Name:             source.detector.scanners.virus_total_scanner
# Created By :      marataj
# Created Date:     2024-11-13
#  ---------------------------------------------------------------------------------------------------------------------

"""
Module containing implementation of the VirusTotal scanner.

"""

import asyncio
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
        self._results: list[IsPhishingResult] | None = None
        self._scan_time: ScanTime | None = None
        self._phishing_threshold = 3

    async def _scan_single_url(self, session: ClientSession, url: str) -> str:
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
        `str`
            Scan ID of scanned URL.

        """
        async with session.post(
            url=f"{self._api_url}urls", headers={"x-apikey": self.__api_key}, data={"url": url}
        ) as response:
            if response.status != HTTPStatus.OK:
                raise HTTPException(f"VirusTotal: Unexpected response status: {HTTPStatus(response.status)}")
            if response.status == HTTPStatus.TOO_MANY_REQUESTS:
                raise VirusTotalApiError("Number of requests per account was exceeded. Check VirusTotal account.")

            body = await response.json()
            return body["data"]["id"]

    async def _scan_urls(self, session: ClientSession) -> list[str]:
        """
        Method responsible for sending asynchronous scan requests for URLs.

        Parameters
        ----------
        session : `ClientSession`
            AioHTTP session for asynchronous HTTP requests.

        Returns
        -------
        `list` [`str`]
            List of scan IDs of scans on the API side.

        """
        tasks = [self._scan_single_url(session, url) for url in self.url_list]
        return await asyncio.gather(*tasks)

    async def _wait_for_analysis_result(self, session: ClientSession, scan_id: str) -> str:
        """
        Method waiting for the  result of the URL analysis. The method executes N requests for result of the analysis,
        and returns the response's content only if the status of the analysis is completed.

        Parameters
        ----------
        session : `ClientSession`
            AioHTTP session for asynchronous HTTP requests.
        scan_id : `str`
            Object containing ID of the scan corresponding to the requested analysis results.

        Returns
        -------
        `dict`
            JSON body of the Virus API response, containing completed URL analysis.

        """
        for _ in range(self._retry_counter):
            async with session.get(
                url=f"{self._api_url}analyses/{scan_id}", headers={"x-apikey": self.__api_key}
            ) as response:
                if response.status == HTTPStatus.TOO_MANY_REQUESTS:
                    raise VirusTotalApiError("Number of requests per account was exceeded. Check VirusTotal account.")

                if response.status != HTTPStatus.OK:
                    raise HTTPException(f"Unexpected status of VirusTotal API response: {HTTPStatus(response.status)}")

                body = await response.json()

                if body["data"]["attributes"]["status"] == "completed":
                    return body

                await asyncio.sleep(self._retry_delay_s)

        raise ValueError("Maximum number of attempts to get the TotalVirus scan result exceeded.")

    async def _get_single_result(self, session: ClientSession, scan_id: str) -> bool:
        """
        Method responsible for collecting and evaluating results.

        Parameters
        ----------
        session : `ClientSession`
            AioHTTP session for asynchronous HTTP requests.
        scan_id : `str`
            Object containing ID of the scan corresponding to the requested analysis results.

        Returns
        -------
        `bool`
            Scan result - True if the URL shall be considered as phishing, False otherwise.

        """
        response_json = await self._wait_for_analysis_result(session, scan_id)
        return self._eval_is_phishing(response_json["data"]["attributes"]["results"])

    async def _get_results(self, session: ClientSession, scan_ids: list[str]) -> list[bool]:
        """
        Method responsible for sending asynchronous requests in order to retrieving results from URL scanning.

        Parameters
        ----------
        session : `ClientSession`
            AioHTTP session for asynchronous HTTP requests.

        scan_ids : `list` [`str`]
            List of scan ID of each URL.

        Returns
        -------
        `list` [`bool`]
            List containing boolean results if URL is considered as phishing, per each URL.

        """
        tasks = [self._get_single_result(session, scan_id) for scan_id in scan_ids]
        return await asyncio.gather(*tasks)

    def _eval_is_phishing(self, results: dict) -> bool:
        """
        Utility function responsible for evaluation if the URL shall be considered as phishing.

        Parameters
        ----------
        results : `dict`
            Dictionary containing results from different Virus Total vendors in following format.
            "Vendor Name": {
                    "method": str,
                    "engine_name": str,
                    "category": str,
                    "result": str,
                },

        Returns
        -------
        `bool`
            True if the URL shall be considered as phishing, False otherwise.

        """
        malicious_num = 0
        for k, v in results.items():
            if v.get("result") == "phishing":
                malicious_num += 1

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
        self._results = [IsPhishingResult(self.__class__.__name__, res) for res in results]
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
