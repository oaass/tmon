#!/usr/bin/env python

import argparse
import threatmonitor
import ConfigParser
from utilities import log
from utilities import flush_log
from utilities import error
from utilities import stdout
from constants import *


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
        error('Unable to read configuration file. %s' % (e), 'fatal')
    except Exception, e:
        error('An error occured reading configuration file. %s' % (e), 'fatal')

    parser = argparse.ArgumentParser(description="Internet Threat Monitor")
    parser.add_argument('--interval', metavar='SEC', help='Update interval. Use this to overrive the value in the configurations', default=config.get('general', 'update_interval'), type=int)
    parser.add_argument('--flush-log', help='Flush log on start', action='store_true')
    parser.add_argument('--debug', help='Enable debug mode', action='store_true')
    args = parser.parse_args()

    if args.flush_log:
        flush_log()

    if args.debug:
        log(LOG_STARTUP)
    main(args, config)
