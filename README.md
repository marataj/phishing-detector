# Phishing Detector

Welcome to Phishing Detector, which is a comprehensive Python application that automates the detection and analysis of 
phishing websites using multiple data sources and detection engines.

## Main features

#### Data sources
Phishing Detector allows to automate collection of the URLs to analyze from following open sources.

* [OpenPhish](https://openphish.com/)
* [PhishStats](https://phishstats.info/)

#### Phishing detections engines
Application core bases on several evaluators engines, called `scanners`, that work independently. Each scanned
URL is checked against following detection engines, that are embedded in the scanners:

* [VirusTotalAPI](https://www.virustotal.com)
* [Google Safe Browsing API](https://developers.google.com/safe-browsing/v4)
* [Google Chrome Safebrowsing](https://safebrowsing.google.com/), which is optional to use.

#### Additional features

* Determining if each URL is alive or dead
* Scann summary, including e.g. scan times per each scanner and percentage values of alive urls.

#### Command-line interface
The aplication exposes CLI to facilitate comparisons and analyses.


## Prerequisites
There are several st

## How to start
The application is compatibile with Python 3.10, Python 3.12

1. Clone the repository.
2. Install requirements:
    ```bash
   pip install -r requirements.txt

3. Complete `.env` file, by filling in the API Keys. [VirusTotal sign up](https://www.virustotal.com/gui/join-us),
[Google Safe Browsing API get started](https://developers.google.com/safe-browsing/v4/get-started).

### Chrome Safe Browsing configuration
Due to the fact, that the evaluation of URLs using Google Chrome Safe Browsing mechanism needs utilize the browser,
there are additional steps required to configure user environment.

**Warning!**
*The Google Chrome Safe Browsing scanning consist in opening the given URLs in automated web browser and checking
its behavior. Due to the security reasons it's recommended to execute detection with Chrome Safe Browsing enabled 
in the separated environment.*

1. Install Playwright-related packages, that are required.
    ```bash
   playwright install

2. Download `Google Chrome` or `Google Chrome Canary` browser.
3. Open the browser and create a new profile.
4. Enable and synchronize the Safe Browsing mechanism - [Manage Enhanced Safe Browsing for your account.](https://support.google.com/accounts/answer/11577602)
5. Synchronizing can take a moment. Test the Safe Browsing manually using [Safe Browsing Tester](https://testsafebrowsing.appspot.com), and make sure, that your browser blocks malicious websites.
6. Find the chrome user-data directory, which by default is under following path: `{username}\AppData\Local\Google\Chrome\User Data`
7. Complete `.env` file with a path to the `Google Chrome` application as `CHROME_PATH`, and path to the User-Data directory, as
`CHROME_USER_DATA_DIR`.

## How to use
### As CLI
### As Python module

## Report description

