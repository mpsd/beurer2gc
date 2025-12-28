# beurer2gc
Parse Beurer HealthManagerPro CSV export files (blood Pressure and weight) and upload to [Garmin Connect](https://connect.garmin.com).
Parsing is done for german csv file format (Beurer export csv files)

## Usage
`python3 upload_beurer2gc.py <csv file>`

uses https://github.com/cyberjunky/python-garminconnect
```shell
dependencies: `pip3 install garminconnect garth requests`
```

## Inspired by / With parts of code from

https://github.com/pedropombeiro/beurer2garminconnect

https://github.com/beep-projects/bpconnect
