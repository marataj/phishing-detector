#  ---------------------------------------------------------------------------------------------------------------------
# Name:             phishing_detector
# Created By :      marataj
# Created Date:     2024-11-20
#  ---------------------------------------------------------------------------------------------------------------------

"""
Module that integrates all the features and exposes CLI.

"""

import argparse
import json
from datetime import datetime
from pathlib import Path

from source.data_collector import DataCollector
from source.detector.detector import Detector


def validate_exe(path: str) -> Path:
    """
    Validates executable path.

    Parameters
    ----------
    path: `str`
        Path to the directory.

    Raises
    ------
    argparse.ArgumentTypeError
        Raises if validation fails.

    Returns
    -------
    `Path`
        Path to the .exe file as a pathlib.Path object.

    """
    path = Path(path)
    if not path.exists():
        raise argparse.ArgumentTypeError(f"File {path} doesn't exist")
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"{path} is not a valid file.")
    if not path.suffix == ".exe":
        raise argparse.ArgumentTypeError(f"File {path} is not executable.")

    return path


def validate_dir(path: str) -> Path:
    """
    Validates directory path.

    Parameters
    ----------
    path: `str`
        Path to the directory.

    Raises
    ------
    argparse.ArgumentTypeError
        Raises if validation fails.

    Returns
    -------
    `Path`
        Path to the directory as a pathlib.Path object.

    """
    path = Path(path)
    if not path.exists():
        raise argparse.ArgumentTypeError(f"Directory {path} doesn't exist")
    if not path.is_dir():
        raise argparse.ArgumentTypeError(f"{path} is not a valid directory.")

    return path


def perform_scan(args: argparse.Namespace) -> None:
    """
    Function containing logic of the command-line interface execution.
    FUnction is responsible for starting scanning and saving the created report.

    Parameters
    ----------
    args: `argparse.Namespace`
        Parsed arguments from command-line interface.

    Raises
    ------
    argparse.ArgumentTypeError
        Raises if validation of the parameters fails.


    """
    if (not any([args.input, args.auto_collect])) or all([args.input, args.auto_collect]):
        raise argparse.ArgumentTypeError(
            "Arguments input and auto_collect are alternatives. Exactly one from them must be provided."
        )

    urls = args.input or DataCollector().get_urls(args.auto_collect)

    print("Start scanning...")

    detector = Detector(args.chrome_safebrowsing_enabled)
    start_time = datetime.now()
    report = detector.scan(urls).to_dict()

    results_dir = args.results_dir or Path(__file__).resolve().parents[0] / "results"
    results_dir.mkdir(exist_ok=True)

    report_name = start_time.strftime("%Y_%m_%d_%H_%M_%S_%f_phishing_scan_report.json")
    report_path = results_dir / report_name

    with open(report_path, "w") as file:
        json.dump(report, file, indent=2)

    print(f"Scanning finished. The report file stored in {report_path}.")


def argparse_config() -> argparse.Namespace:
    """
    Parses arguments passed through the command-line interface.

    Returns
    -------
    `argparse.Namespace`
        Namespace containing required arguments.

    """
    parser = argparse.ArgumentParser(
        description="CLI client for Phishing-detector application. It allows to scan the URLs against phishing using"
        "several available detector engines."
    )

    parser.add_argument("--input", type=str, action="extend", nargs="+", help="User defined URLs to be scanned.")
    parser.add_argument(
        "--auto-collect", type=int, help="Number of URLs to be automatically collected from the open sources."
    )
    parser.add_argument(
        "--chrome-safebrowsing-enabled", action="store_true", help="Activates Chrome Safe Browser Scanning."
    )
    parser.add_argument(
        "-r", "--results-dir", type=validate_dir, help="Path to the directory for saving the scan report."
    )

    return parser.parse_args()


def cli() -> None:
    """
    CLI main method containing argument parsing and calling the CLI logic execution.

    """
    args = argparse_config()
    perform_scan(args)


if __name__ == "__main__":
    cli()
