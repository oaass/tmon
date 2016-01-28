TMon - Internet Threat Monitor
===

TMon is a small tool which monitors the current online threat levels. It has a green, yellow, red level indicator, and information about top attacked ports and countries. It also provides information about the unique attacking sources (IPs)

The script gathers its information from the [DShield API](https://isc.sans.edu/api/) provided by SANS.

## Dependencies

These are the modules used by TMon

* argparse
* datetime
* ConfigParser
* time
* requests
* os
* fcntl
* termios
* struct
* sys
* termcolor
* json
* pygeoip
* IPy

## TODO

* Add more port services
* Add functionality for update snapshots
* Add single snapshot functionality (instead of continuous monitoring)
* Add attack difference display to see if anything has change since last update

## Set up

Before you can use start using TMon you need to do the following

* Download and extract GeoIP.dat from [maxmind](http://dev.maxmind.com/geoip/legacy/geolite/) ([direct download](http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz))
* Rename config-dist.cfg to config.cfg
* Change the value of *filepath* under the *geolocation* section to point to your GeoIP.dat file

## Options

```
-h, --help         show this help message and exit
--interval SEC     Update interval. Use this to overrive the value in the
                   configurations
--flush-log        Flush log on start
--debug            Enable debug mode
--max-ports #      Max number of ports to display (Default: 10)
--max-ips #        Max number of sources to display (Default: 5)
--max-countries #  Max number of countries to display (Default: 10)
```

## Usage

```
usage: tmon.py [-h] [--interval SEC] [--flush-log] [--debug] [--max-ports #]
               [--max-ips #] [--max-countries #]
```

## Screenshot

![Image](http://imagizer.imageshack.com/img673/8217/HwMyZb.png)

## Change log

**2016-01-28** - *v1.0*
---
[+] Fixed bugs
[+] Added new command line options

**2015-03-16** - *v0.1-alpha*
```
[+] Initial release
```
