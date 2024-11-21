#  ---------------------------------------------------------------------------------------------------------------------
# Name:             source.detector.scanners.chrome_safe_browsing_scanner
# Created By :      marataj
# Created Date:     2024-11-18
#  ---------------------------------------------------------------------------------------------------------------------

"""
Module containing implementation of the Chrome Safe Browsing scanner using playwright.

"""

import asyncio
from datetime import datetime
from typing import Literal, Tuple

from aiohttp import ClientSession
from playwright._impl._errors import Error as PlaywrightError
from playwright._impl._errors import TargetClosedError
from playwright.async_api import (BrowserContext, Page, Playwright,
                                  async_playwright)

from source.detector.report import (ChromeSafeBrowsingResult,
                                    ChromeSafeBrowsingStats, IsPhishingResult,
                                    ScanTime, SubReport)
from source.detector.scanners.scanner import Scanner
from source.settings import CHROME_PATH, CHROME_USER_DATA_DIR

__all__ = ["ChromeSafeBrowsingScanner"]


class ChromeSafeBrowsingScanner(Scanner):
    """
    Class responsible for scanning the URLs with using Google Safe Browsing in Google Chrome browser.

    """

    def __init__(self, url_list: list[str]) -> None:
        """
        Initializes the scanner instance.

        Raises
        ------
        AttributeError
            Raises when lack of all the required attributes.

        Parameters
        ----------
        url_list : `list` [`str`]
            List of the URLs to be scanned.

        """
        super().__init__(url_list)
        self._chrome_path = CHROME_PATH
        self._user_data_dir = CHROME_USER_DATA_DIR
        if not all([self._chrome_path, self._user_data_dir]):
            AttributeError("Lack of required attribute. Both CHROME_PATH and CHROME_USER_DATA_DIR are required.")

        self._results: dict[str, ChromeSafeBrowsingResult] | None = None
        self._scan_time: ScanTime | None = None
        self._sb_blocked_number: int | None = None
        self._no_sb_blocked_number: int | None = None

    async def _scan_url(self, page: Page, url: str) -> bool | None:
        """
        method responsible for opening the appropriate page on the tab and checking if it is blocked.

        Parameters
        ----------
        page: `Page`
            Playwright Chrome Page.
        url: `str`
            URL to be checked.

        Returns
        -------
        `bool` | `None`
            True if the website was blocked, False otherwise. Returns None when the website is unavailable.

        """
        is_blocked = False
        try:
            await page.goto(url)

        except PlaywrightError as e:
            # Website was not loaded correctly
            is_blocked = None
            if "net::ERR_BLOCKED_BY_CLIENT" in e.message:
                # Chrome browser blocked the website content
                is_blocked = True

        except Exception:
            # Exception raised during loading the website
            is_blocked = None

        finally:
            await page.close()
            return is_blocked

    async def _scan_urls(
        self, context: BrowserContext, mode: Literal["no_sb", "sb"]
    ) -> Tuple[list[IsPhishingResult], int]:
        """
        Method responsible for scanning multiple all the URLs through the given browser context.

        Parameters
        ----------
        context: `BrowserContext`
            Browser context for opening the pages for each URL.
        mode: `Literal`
            Determines the testing context the method is called in. "no_sb" means no safebrowsing enabled, "sb" means
            safebrowsing enabled.

        Returns
        -------
        `list` [`IsPhishingResult`]
            List of objects representing results per each URL.
        `int`
            Aggregate number of blocked pages.

        """
        pages = await asyncio.gather(*[context.new_page() for _ in range(len(self.url_list))])
        tasks = [self._scan_url(page, url) for page, url in zip(pages, self.url_list)]
        results = await asyncio.gather(*tasks)
        return [IsPhishingResult(self.__class__.__name__ + "_" + mode, result) for result in results], results.count(
            True
        )

    async def _scan_safebrowsing(self, playwright: Playwright) -> list[IsPhishingResult]:
        """
        Method responsible for testing on the browser with safebrowsing enabled.

        Parameters
        ----------
        playwright: `Playwright`
            Instance of playwright.

        Returns
        -------
        `list` [`IsPhishingResult`]
            List of object containing information about scanning result in safebrowsing context.

        """
        context = await playwright.chromium.launch_persistent_context(
            executable_path=self._chrome_path,
            user_data_dir=self._user_data_dir,
            headless=False,
        )
        results, blocked_num = await self._scan_urls(context, "sb")
        await context.close()

        self._sb_blocked_number = blocked_num
        return results

    async def _scan_no_safebrowsing(self, playwright: Playwright) -> list[IsPhishingResult]:
        """
        Method responsible for testing on the browser without safebrowsing enabled.

        Parameters
        ----------
        playwright: `Playwright`
            Instance of playwright.

        Returns
        -------
        `list` [`IsPhishingResult`]
            List of object containing information about scanning result in no safebrowsing context.

        """
        browser = await playwright.chromium.launch(executable_path=self._chrome_path, headless=False)
        context = await browser.new_context()

        results, blocked_num = await self._scan_urls(context, "no_sb")
        await browser.close()

        self._no_sb_blocked_number = blocked_num
        return results

    async def _scan(self) -> dict[str, ChromeSafeBrowsingResult]:
        """
        The main scanning method. It's responsible for creating the Playwright instance, running the scans in both
        safebrowsing and no safebrowsing contexts, ordering the scanning results.
        TODO: turn off browser GUI displaying without using headless=True

        Raises
        ------
        `RuntimeError`
            Raises when the context passed to the scanner is manually opened in the browser.

        Returns
        -------
        `dict` [`str`, `ChromeSafeBrowsingResult`]
            Dictionary containing ChromeSafeBrowsingResult objects as a values per each scanned URL as a keys.

        """
        async with async_playwright() as playwright:
            try:
                results_no_sb = await self._scan_no_safebrowsing(playwright)
                results_sb = await self._scan_safebrowsing(playwright)
            except TargetClosedError:
                raise RuntimeError(
                    "Chrome browser instance with the same context as passed to the scanner must be closed during the test."
                )
            return {
                url: ChromeSafeBrowsingResult(no_sb, sb)
                for url, no_sb, sb in zip(self.url_list, results_no_sb, results_sb)
            }

    async def run(self, session: ClientSession) -> None:
        """
        Method that runs the scan of the URLs.

        Parameters
        ----------
        session : `ClientSession`
            Session for execution of asynchronous HTTP requests.

        """
        start_time = datetime.now()
        self._results = await self._scan()
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
        no_sb_blocked_percentage = self._no_sb_blocked_number / len(self.url_list) * 100
        sb_blocked_percentage = self._sb_blocked_number / len(self.url_list) * 100
        chrome_stats = ChromeSafeBrowsingStats(
            self._no_sb_blocked_number, no_sb_blocked_percentage, self._sb_blocked_number, sb_blocked_percentage
        )

        return SubReport(self.__class__.__name__, self._results, [self._scan_time, chrome_stats])
