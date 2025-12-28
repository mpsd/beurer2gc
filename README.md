# beurer2gc
Parse Beurer HealthManagerPro CSV export files (blood pressure and weight measurements) and upload to [Garmin Connect](https://connect.garmin.com).
Parsing is done for german csv file format (Beurer export csv files). The script is trying to avoid duplicate uploads by downloading measurement history from Garmin Connect.

## Usage
Export csv for `blood pressure` (Blutdruck) and `weight` (Gewicht) measurements from Beurer HealthManager Pro.

Call `python3 upload_beurer2gc.py <csv file>` to upload to Garmin Connect.

## Dependencies
uses https://github.com/cyberjunky/python-garminconnect
```shell
pip3 install garminconnect garth requests
```

## Inspired by / With parts of code from

https://github.com/pedropombeiro/beurer2garminconnect

https://github.com/beep-projects/bpconnect
