#!/usr/bin/env python

import argparse
import datetime
import threatmonitor
import ConfigParser
from time import sleep
from utilities import *

def main(args, config):
    if args.debug:
        log('Initializing threatmonitor.ThreatMonitor', 'debug')
    tmon = threatmonitor.ThreatMonitor(args, config)
    tmon.monitor()

if __name__ == '__main__':

    try:
        config = ConfigParser.ConfigParser()
        config.readfp(open('config.cfg'))
    except IOError, e:
        error('Unable to read configuration file. %s'%(e), 'fatal')
    except Exception, e:
        error('An error occured when trying to read configuration file. %s'%(e), 'fatal')

    parser = argparse.ArgumentParser(description="Internet Threat Monitor")
    parser.add_argument('--interval', metavar='SEC', help='Update interval. Use this to overrive the value in the configurations', default=config.get('general', 'update_interval'), type=int)
    parser.add_argument('--flush-log', help='Flush log on start', action='store_true')
    parser.add_argument('--debug', help='Enable debug mode', action='store_true')
    parser.add_argument('--max-ports', metavar='#', help='Max number of ports to display', default=config.get('general', 'max_ports'), type=int)
    parser.add_argument('--max-ips', metavar='#', help='Max number of sources to display', default=config.get('general', 'max_ips'), type=int)
    parser.add_argument('--max-countries', metavar='#', help='Max number of countries to display', default=config.get('general', 'max_countries'), type=int)
    args = parser.parse_args()

    if args.flush_log:
        flushlog()

    if args.debug:
        log('Starting TMON')
    main(args, config)
