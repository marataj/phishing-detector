Phishing Detector
=================

Welcome to Phishing Detector, which is a comprehensive Python application that automates the detection and analysis of 
phishing websites using multiple data sources and detection engines.

Main features
-------------
### URL data collection

Phishing Detector allows to automate collection of the URL lists from following open sources.

* [OpenPhish](https://openphish.com/)
* [PhishStats](https://phishstats.info/)

#### Phishing detections engines
Application bases on multiple phishing detection engines, which work independently. Each scanned
URL is checked against following detection engines:

* [VirusTotalAPI](https://www.virustotal.com)
* [Google Safe Browsing API](https://developers.google.com/safe-browsing/v4)
* [Google Chrome Safebrowsing](https://safebrowsing.google.com/), which is optional to use.

### Additional features

* Determining if each scanned URL is alive or not.

### Command-line interface
The aplication exposes CLI to facilitate comparisons and analyses. Using the CLI the user can scan provided set of URLs,
or scan auto-collected URLs, for engines comparison purposes. Results are summarized and saved to a json file.

How to start
------------
The application is compatible with Python 3.10.

1. Clone the repository.
2. Install requirements:
    ```bash
   pip install -r requirements.txt

3. Complete `.env` file, by filling in the API Keys. [VirusTotal sign up](https://www.virustotal.com/gui/join-us),
[Google Safe Browsing API get started](https://developers.google.com/safe-browsing/v4/get-started).

### Chrome Safe Browsing configuration
Due to the fact, that the evaluation of URLs using Google Chrome Safe Browsing mechanism needs access to the browser,
there are additional steps required in order to configure user environment.

**Warning!**
*The Google Chrome Safe Browsing scanning based on opening the suspicious URLs in automated web browser. 
Due to the security reasons it's recommended to execute scan with Chrome Safe Browsing enabled 
in the separated environment.*

1. Install Playwright-related packages, that are required.
    ```bash
   playwright install

2. Download `Google Chrome` or `Google Chrome Canary` browser.
3. Open the browser and create a new profile.
4. Enable and synchronize the Safe Browsing mechanism - [Manage Enhanced Safe Browsing for your account.](https://support.google.com/accounts/answer/11577602)
5. Synchronization can take a moment. Test the Safe Browsing manually using [Safe Browsing Tester](https://testsafebrowsing.appspot.com), and make sure that your browser blocks malicious websites.
6. Find the chrome user-data directory, which by default is under following path: `{username}\AppData\Local\Google\Chrome\User Data`
7. Complete `.env` file with a path to the `Google Chrome` application as `CHROME_PATH`, and path to the User-Data directory, as
`CHROME_USER_DATA_DIR`.

How to use
----------
### As CLI
The application exposes the CLI in the `run.py` script, to automating URLs scan and facilitate engines comparisons and result 
analyses. 
To use it type following command
 
```python run.py <arguments>```

CLI allows to trigger an automated scan with following flow:
1. Collecting the URLs to be scanned (from the user input or auto-collecting from available sources).
2. Scanning URLs using multiple detection engines.
3. Generating the report, containing summarized results, and saving it to the file.

Avaliable CLI arguments:
* Input.  
using `--input url1 url2 url3 ....` the user can pass custom URLs to scan. It's a multi-value
argument, so the user can pass multiple URLs in a row.  
*This attribute can be used only if `--auto-collect` argument is disabled.*

   Example:

   ```python run.py --input https://website1.com https://website2.com```


* Auto-collect.  
`--auto-collect <number of URLs to collect>` argument enables auto-collection of the URLs.  
*Can be used only if custom URLs are not passed through the `--input` argument.*  
Additionally, the user can choose a specific data source, using following attributes:
   * OpenPhish: adding `--open-phish` sets OpenPhish.com as a data source.
   * PhishStats: adding `--phish-stats` sets PhishStats.com as a data source.
  
   Example:

   ```bash
  python run.py --auto-collect 10 # performs scan of 10 URLs in total, collected both from OpenPhish and PhishStats
  python run.py --auto-collect 7 --open-phish # performs scan of 7 URLs collected from OpenPhish
  python run.py --auto-collect 50 --phish-stats # performs scan of 50 URLs collected from PhishStats
   ```
  
* Chrome Safe Browsing enabling.  
using `--chrome-safebrowsing-enabled` the user can include Chrome Safe Browsing scanner to the scan. 
Due to the security and additional configuration reasons this option is required to be activated manually.

   Example:

   ```python run.py --input https://website1.com https://website2.com --chrome-safebrowsing-enabled```


* Results Directory.  
using `--results-dir <path to the directory>` the user can point to a custom directory where reports will be saved in.
In case of lack of this argument, the default results directory is `\phishing-detector\results`

   Example:

   ```python run.py --input https://website1.com https://website2.com --results-dir C:\temp\phishing_results```
 
 
### As Python module (for developers)
The user can utilize the phishing-detector as a python module by importing specific objects into their custom scripts.

1. DataCollector.  
`DataCollector` class, from `source.data_collector` module, automates URL collection. Its public methods allow the user
to collect the URLs from supported open sources.

   Example:

   ```python
   >>>from data_collector import DataCollector
   
   >>>d=DataCollector()
   >>>urls=d.get_urls_openphish(50)
   >>>urls
   ['https://website1.com', 'https://website2.com', 'https://website3.com'....]
   ```

2. Detector.  
`Detector` class from `source.detector.detector` module, is responsible for scanning of the URLs. Class 
exposes `scan()` method, which takes list of URLs as an argument and triggers their scan.  
The method returns `Report` object,
contained in `source.detector.report` module, that is described below in this document.

   Example:

   ```python
   >>>from data_collector import DataCollector
   >>>from source.detector.detector import Detector
   
   >>>d=DataCollector()
   >>>urls=d.get_urls_openphish(50)
   >>>detector=Detector()
   >>>report=detector.scan(urls)
   Report(url_results=[URLResult(url='https://website1.com', is_alive=IsAliveResult(is_alive=True, response_code=200), ...
   ```
   
3. Report.  
The `source.detector.report` module, contains the structure of the final report, that is basing on dataclasses. 
The output from the `detector.scan()` method is represented of `Report` type.  
It exposes two methods returning the report content in the different formats:

   * `to_dict` - returns report content as dictionary.
   * `to_json` - returns report content in json format.

    Example:

   ```python
   >>>from data_collector import DataCollector
   >>>from source.detector.detector import Detector
   
   >>>d=DataCollector()
   >>>urls=d.get_urls_openphish(50)
   >>>detector=Detector()
   >>>report=detector.scan(urls)
   Report(url_results=[URLResult(url='http://website1.com/', is_alive=IsAliveResult(is_alive=True, response_code=200), ...
   >>>report.to_dict()
   {'url_results': [{'url': 'http://website1.com/', 'is_alive': {'is_alive': True, 'response_code': 200}, 
   >>>report.to_json()
   "url_results": [
    {
      "url": "https://website1.com",
      "is_alive": {
        "is_alive": true,
        "response_code": 200
      },
    ...
      
   ```

4. Scanners.  
The term 'scanner' denotes a class that encapsulates the logic of a specific, single detection mechanism. 
The `source.detector.scanners` package is containing all the implemented scanners.  
Available scanners:
   * `source.detector.scanners.alive_scanner.AliveScanner` 
   * `source.detector.scanners.chrome_safe_browsing_scanner.ChromeSafeBrowsingScanner` 
   * `source.detector.scanners.google_safe_browsing_api_scanner.GoogleSafeBrowsingAPIScanner` 
   * `source.detector.scanners.virus_total_scanner.VirusTotalScanner`

Report structure description
----------------------------

Example json report:

```json
{
  "url_results": [
    {
      "url": "https://website1.com",
      "is_alive": {
        "is_alive": true,
        "response_code": 200
      },
      "is_phishing_sub_results": [
        {
          "scanner_name": "VirusTotalScanner",
          "is_phishing": true
        },
        {
          "scanner_name": "GoogleSafeBrowsingAPIScanner",
          "is_phishing": true
        },
        {
          "scanner_name": "ChromeSafeBrowsingScanner_no_sb",
          "is_phishing": false
        },
        {
          "scanner_name": "ChromeSafeBrowsingScanner_sb",
          "is_phishing": true
        }
      ],
      "is_phishing": true
    }, 
    ... 
    }
  ],
    "statistics": {
    "urls_number": 10,
    "scanners_times_stats": [
      {
        "scanner_name": "VirusTotalScanner",
        "scan_time": "0:00:01.023387"
      },
      {
        "scanner_name": "GoogleSafeBrowsingAPIScanner",
        "scan_time": "0:00:00.242773"
      },
      {
        "scanner_name": "AliveScanner",
        "scan_time": "0:00:00.209326"
      },
      {
        "scanner_name": "ChromeSafeBrowsingScanner",
        "scan_time": "0:00:03.174550"
      }
    ],
    "alive_stats": {
      "alive_urls": 10,
      "alive_urls_pct": 100.0
    },
    "chrome_safebrowsing_stats": {
      "no_sb_blocked_urls": 0,
      "no_sb_blocked_urls_pct": 0.0,
      "sb_blocked_urls": 10,
      "sb_blocked_urls_pct": 100.0
    },
    "scanning_time": "0:00:03.174550"
  }
}
```

The final report consist in two main fields: 
* `url_results` - contains list of evaluation results per each scanned URL.
* `statistics` - contains overall scanning statistics.

Each item in `url_results` includes: 
* `url` - scanned url.
* `is_alive`- indicates within the page is alive.
* `is_phishing_sub_results` - contains evaluation result of each active scanner.
* `is_phishing` - indicates whether the page is considered as phishing. The value is a logical disjunction (logical OR) of the sub-results. 

The `statistics` field contains:
* `url_number` - the aggregate number of scanned URLs.
* `scanners_times_stats` - contains a list of execution time of each scanner.
* `alive_stats` - contains number and percentage value of URLs that are alive.
* `chrome_safebrowsing_stats` - contains number and percentage values of blocked websites in each mode - safebrowsing 
enabled (`sb` prefix), and safebrowsing disabled (`no_sb` prefix).
* `scanning_time` - overall execution time.
