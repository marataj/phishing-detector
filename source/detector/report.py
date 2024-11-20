#  ---------------------------------------------------------------------------------------------------------------------
# Name:             detector.report
# Created By :      marataj
# Created Date:     2024-11-17
#  ---------------------------------------------------------------------------------------------------------------------

"""
Module containing structure and logic of the final report.

"""

import datetime
import json
from dataclasses import asdict, dataclass, field

__all__ = [
    "ChromeSafeBrowsingStats",
    "AliveStats",
    "ScanTime",
    "Stats",
    "IsPhishingResult",
    "IsAliveResult",
    "ChromeSafeBrowsingResult",
    "URLResult",
    "Report",
    "SubReport",
    "generate_report",
    "report_dict_factory",
]


@dataclass
class ChromeSafeBrowsingStats:
    """
    Class represents statistics related to Chrome Safebrowsing scan. Chows number and percentage value of websited that
    were blocked by Chrome with and without safebrowsing enabled.

    """

    no_sb_blocked_number: int
    no_sb_blocked_percentage: float
    sb_blocked_number: int
    sb_blocked_percentage: float


@dataclass
class AliveStats:
    """
    Class represents statistics related to alive/dead websites.

    """

    alive_number: int
    alive_percentage: float


@dataclass
class ScanTime:
    """
    Class represents statistics of scanning time of each scanner.

    """

    scanner_name: str
    scann_time: datetime.timedelta


@dataclass
class Stats:
    """
    Class represents Stats group. Stats group contains information about scann times per each scanner, overall scann
    time and statistics about alive/dead websites.

    """

    sub_scans_time: list[ScanTime]
    alive_stats: AliveStats = None
    chrome_safebrowsing: ChromeSafeBrowsingStats = None
    scan_time: datetime.timedelta | None = field(init=False)

    def __post_init__(self):
        """
        Assigns longer scann time to the overall scanning time.

        """
        try:
            self.scan_time = max([sub_time.scann_time for sub_time in self.sub_scans_time])
        except ValueError:
            self.scan_time = None


@dataclass
class IsPhishingResult:
    """
    Class represents single scanner's verdict about being a phishing site

    """

    scanner_name: str
    is_phishing: bool | None


@dataclass
class IsAliveResult:
    """
    Class represents verdict about being active/dead website. Additionally, there is a response code for a plain get request.

    """

    is_alive: bool
    response_code: int


@dataclass
class ChromeSafeBrowsingResult:
    """
    Class represents the verdict of Chrome Safebrowsing scanner, containing information if the website was detected by
    Chrome browser with safebrowsing enabled and without it.

    """

    no_safebrowsing: IsPhishingResult
    safebrowsing: IsPhishingResult


@dataclass
class URLResult:
    """
    Class represents a set of scanning results for single URL.

    """

    url: str
    is_alive: IsAliveResult
    is_phishing_sub_results: list[IsPhishingResult]
    is_phishing: bool | None = field(init=False)

    def __post_init__(self):
        """
        Assigns an overall is_phishing result, as a logical disjunction of sub-results (results of each scanner).

        """
        if not self.is_phishing_sub_results:
            self.is_phishing = None
            return

        self.is_phishing = any([sub_res.is_phishing for sub_res in self.is_phishing_sub_results])


@dataclass
class Report:
    """
    Class represents the final report structure.

    """

    url_results: list[URLResult]
    stats: Stats

    def to_dict(self) -> dict:
        return asdict(self, dict_factory=report_dict_factory)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


@dataclass
class SubReport:
    """
    Class represents the sub-report structure, which is a result type for scanners.
    The key of url_results `dict` must be the URL value.

    """

    scanner_name: str
    url_results: dict[str, IsPhishingResult | IsAliveResult | ChromeSafeBrowsingResult]
    stats: list[ScanTime | AliveStats | ChromeSafeBrowsingStats]


def generate_report(sub_reports: list[SubReport], urls: list[str]) -> Report:
    """
    Function responsible for generating the final report based on the sub-reports from detector's scanners.

    Parameters
    ----------
    sub_reports: `list` [`SubReport`]
        List containing sub-reports from scan.
    urls: `list` [`str`]
        List containing urls used in the scan.

    Returns
    -------
    `Report`
        The final report.

    """
    url_results = []
    for url in urls:
        is_phishing_sub_results = []
        is_alive = None
        for sub_report in sub_reports:
            url_result = sub_report.url_results[url]
            if isinstance(url_result, ChromeSafeBrowsingResult):
                is_phishing_sub_results.append(url_result.no_safebrowsing)
                is_phishing_sub_results.append(url_result.safebrowsing)
            elif isinstance(url_result, IsPhishingResult):
                is_phishing_sub_results.append(url_result)
            elif isinstance(url_result, IsAliveResult):
                is_alive = url_result
        url_results.append(URLResult(url, is_alive, is_phishing_sub_results))

    sub_scans_time = []
    alive_stats = None
    chrome_stats = None
    for sub_report in sub_reports:
        for stat in sub_report.stats:
            if isinstance(stat, ScanTime):
                sub_scans_time.append(stat)
            elif isinstance(stat, AliveStats):
                alive_stats = stat
            elif isinstance(stat, ChromeSafeBrowsingStats):
                chrome_stats = stat

    stats = Stats(sub_scans_time, alive_stats, chrome_stats)

    return Report(url_results, stats)


def report_dict_factory(data: dict) -> dict:
    """
    Function provided to be passed as a `dict_factory` parameter of `dataclasses.asdict` method, allowing for seamless
    conversion of the final report to json format, by formatting `datetime.timedelta` objects to string.

    Parameters
    ----------
    data: `dict`
        Input dictionary

    Returns
    -------
    `dict`
        Output dictionary.

    """
    return {key: (str(value) if isinstance(value, datetime.timedelta) else value) for key, value in data}
