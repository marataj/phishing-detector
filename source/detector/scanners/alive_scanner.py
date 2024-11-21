#  ---------------------------------------------------------------------------------------------------------------------
# Name:             source.detector.scanners.alive_scanner
# Created By :      marataj
# Created Date:     2024-11-16
#  ---------------------------------------------------------------------------------------------------------------------

"""
Module containing implementation of the Alive Scanner.

"""

import asyncio
from datetime import datetime
from http import HTTPStatus
from typing import Tuple

from aiohttp import ClientSession
from aiohttp.client_exceptions import ClientConnectorError

from source.detector.report import (AliveStats, IsAliveResult, ScanTime,
                                    SubReport)
from source.detector.scanners.scanner import Scanner

__all__ = ["AliveScanner"]


class AliveScanner(Scanner):
    """
    Scanner evaluating if website is alive or not.

    """

    def __init__(self, url_list: list[str]) -> None:
        """
        Initializes the scanner instance.

        Parameters
        ----------
        url_list : `list` [`str`]
            List of the URLs to be scanned.

        """
        super().__init__(url_list)
        self._results: dict[str, IsAliveResult] | None = None
        self._scan_time: ScanTime | None = None
        self.request_timeout = 3
        self._dead_codes = [
            HTTPStatus.BAD_REQUEST,
            HTTPStatus.FORBIDDEN,
            HTTPStatus.NOT_FOUND,
            HTTPStatus.REQUEST_TIMEOUT,
            HTTPStatus.GONE,
            HTTPStatus.INTERNAL_SERVER_ERROR,
            HTTPStatus.BAD_GATEWAY,
            HTTPStatus.SERVICE_UNAVAILABLE,
            HTTPStatus.GATEWAY_TIMEOUT,
            HTTPStatus.HTTP_VERSION_NOT_SUPPORTED,
        ]

    def _evaluate_response_code(self, response_code: int) -> bool:
        """
        Utility method checking if the website is alive based on the response code.

        Parameters
        ----------
        response_code: `int`
            Status code of the response.

        Returns
        -------
        `bool`
            Website status - returns True if website is alive, False otherwise.

        """
        is_alive = True
        if response_code in self._dead_codes:
            is_alive = False

        return is_alive

    async def _scan_url(self, session: ClientSession, url: str) -> Tuple[str, bool, int | None]:
        """
        Method responsible for scanning of the single URL.

        Parameters
        ----------
        session : `ClientSession`
            AioHTTP session for asynchronous HTTP requests.
        url : `str`
            URL to be scanned.

        Returns
        -------
        `Tuple` [`str`, `bool`, `int` | `None`]
            Tuple containing scanned URL, evaluation result and response status code respectively. If TimeoutError or
            ClientConnectorError was raised, the response code is set to None.

        """
        try:
            async with session.get(url, timeout=self.request_timeout) as response:
                return url, self._evaluate_response_code(response.status), response.status

        except (asyncio.TimeoutError, ClientConnectorError):
            return url, False, None

    async def _scan_urls(self, session: ClientSession) -> dict[str, Tuple[bool, int | None]]:
        """
        Method responsible for scanning URLs.

        Parameters
        ----------
        session : `ClientSession`
            AioHTTP session for asynchronous HTTP requests.

        Returns
        -------
        TODO: adjust types to report types
        `dict` [`str`, `Tuple`[`bool`, `int` | `None`]]
            Dictionary with scanned URL as a key and Tuple containing scanning result and response code as a value.

        """
        tasks = [self._scan_url(session, url) for url in self.url_list]
        results = await asyncio.gather(*tasks)
        return {url: IsAliveResult(is_alive, status_code) for url, is_alive, status_code in results}

    async def run(self, session: ClientSession) -> None:
        """
        Method that runs the scan of the URLs.

        Parameters
        ----------
        session : `ClientSession`
            Session for execution of asynchronous HTTP requests.

        """
        start_time = datetime.now()
        self._results = await self._scan_urls(session)
        self._scan_time = ScanTime(self.__class__.__name__, datetime.now() - start_time)

    def generate_report(self) -> SubReport:
        """
        Method responsible for generating the SubReport from the Alive Scanner scan.

        Raises
        ------
        ValueError
            Raises when there is no results to be processed.

        Returns
        -------
        `SubReport`
            SubReport from the Alive Scanner.

        """

        alive_number = len(list(filter(lambda x: x.is_alive is True, self._results.values())))
        alive_percentage = alive_number / len(self.url_list) * 100

        if not (self._results and self._scan_time):
            raise ValueError("Report generating suspended - lack of results to be processed.")

        return SubReport(
            self.__class__.__name__, self._results, [self._scan_time, AliveStats(alive_number, alive_percentage)]
        )
