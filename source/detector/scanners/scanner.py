#  ---------------------------------------------------------------------------------------------------------------------
# Name:             detector.scanners.scanner
# Created By :      marataj
# Created Date:     2024-11-13
#  ---------------------------------------------------------------------------------------------------------------------

"""
Module containing the abstract class defining the basic interface of each scanner subclass.

"""

from abc import ABC, abstractmethod
from typing import Any

from aiohttp import ClientSession

__all__ = ["Scanner"]


class Scanner(ABC):
    """
    Abstract class defining the interface for each scanner subclass.

    """

    @abstractmethod
    def __init__(self, url_list: list[str]) -> None:
        """
        Initializes the scanner instance.

        Parameters
        ----------
        url_list : `list` [`str`]
            List of the URLs to be scanned.

        """
        self.url_list = url_list

    @abstractmethod
    async def run(self, session: ClientSession) -> None:
        """
        Abstract method that runs the scan of the URLs. Each scanning shall implement its own logic, depending on the
        mechanism requirements.

        Parameters
        ----------
        session : `ClientSession`
            Session for execution of asynchronous HTTP requests.

        """

    @abstractmethod
    def generate_report(self) -> dict[str, Any]:
        """
        Abstract method that generates the scanning report. Each scan shall implement its onw logic, depending on the
        features it provides.

        Returns
        -------
        `dict` [`str`, `Any`]
            Report as the dictionary object.
            TODO: report structure must be assumed

        """
