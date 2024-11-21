#  ---------------------------------------------------------------------------------------------------------------------
# Name:             source.detector.scanners.google_safe_browsing_api_scanner
# Created By :      marataj
# Created Date:     2024-11-13
#  ---------------------------------------------------------------------------------------------------------------------

"""
Module containing implementation of the Google Safe Browsing API scanner.

"""

import json
from datetime import datetime
from http import HTTPStatus
from http.client import HTTPException

from aiohttp import ClientSession

from source.detector.report import IsPhishingResult, ScanTime, SubReport
from source.detector.scanners.scanner import Scanner
from source.settings import GSB_API_KEY

__all__ = ["GSBAPIScanner"]

class GoogleSafeBrowsingApiError(Exception):
    """
    Exception represents API errors.

    """
    pass


class GSBAPIScanner(Scanner):
    """
    Class responsible for scanning the URLs with using Google Safe Browsing API v4.

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
        self.__api_key = GSB_API_KEY
        if not self.__api_key:
            raise AttributeError("Lack of VirusTotal API KEY.")
        self._api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.__api_key}"
        self._results: dict[str, IsPhishingResult] | None = None
        self._scan_time: ScanTime | None = None

    def _prepare_request_payload(self) -> str:
        """
        Utility method preparing the payload for scan request.

        Returns
        -------
        `str`
            Payload prepared for the scanning request.

        """
        return json.dumps(
            {
                "client": {"clientId": "phishing_detector", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url} for url in self.url_list],
                },
            }
        )

    def _process_results(self, resp_body: dict) -> None:
        """
        Method responsible for processing the result of the scanning. The value in the self._results dictionary is set
        to True for each URL detected as phishing.

        Parameters
        ----------
        resp_body: `dict`
            The body of the scanning response.

        """
        results = {url: False for url in self.url_list}
        if "matches" in resp_body:
            for match in resp_body["matches"]:
                results[match["threat"]["url"]] = True

        self._results = {url: IsPhishingResult(self.__class__.__name__, result) for url, result in results.items()}

    async def _scan_urls(self, session: ClientSession) -> dict:
        """
        Method that sends the URLs scanning request to the engine API.

        Parameters
        ----------
        session : `ClientSession`
            AioHTTP session for asynchronous HTTP requests.

        Raises
        ------
        HTTPException
            Raises after unexpected status of API response.
        GoogleSafeBrowsingApiError
            Raises after exceeding the number of request per account.

        Returns
        -------
        `dict`
            Response body containing information about detected malicious URLs.

        """
        async with session.post(
            self._api_url, headers={"Content-Type": "application/json"}, data=self._prepare_request_payload()
        ) as response:
            if response.status != HTTPStatus.OK:
                raise HTTPException(f"Google Safe Browsing API: Unexpected response status: {HTTPStatus(response.status)}")
            if response.status == HTTPStatus.TOO_MANY_REQUESTS:
                raise GoogleSafeBrowsingApiError("Number of requests per account was exceeded. Check Google account.")

            body = await response.json()
            return body

    async def run(self, session: ClientSession) -> None:
        """
        TODO: verify correctness of all the docstrings
        Method that runs the scan of the URLs.

        Parameters
        ----------
        session : `ClientSession`
            Session for execution of asynchronous HTTP requests.

        """
        start_time = datetime.now()
        body = await self._scan_urls(session)
        self._process_results(body)
        self._scan_time = ScanTime(self.__class__.__name__, datetime.now() - start_time)

    def generate_report(self) -> SubReport:
        """
        Method responsible for generating the SubReport from the GSB scan.

        Raises
        ------
        ValueError
            Raises when there is no results to be processed.

        Returns
        -------
        `SubReport`
            SubReport from the GSB scan.

        """
        if not (self._results and self._scan_time):
            raise ValueError("Report generating suspended - lack of results to be processed.")
        return SubReport(self.__class__.__name__, self._results, [self._scan_time])
