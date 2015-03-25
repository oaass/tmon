#!/usr/bin/env python

import dshield
import datetime
import os
import fcntl
import termios
import struct
import sys
from termcolor import colored
from time import sleep
from utilities import log
from utilities import error
from utilities import debug
from utilities import warning
from utilities import fatal
from utilities import stdout
from utilities import get_default_port_service
from constants import *


class ThreatMonitor():

    # Seconds between each update
    update_interval = None

    # Configuration
    config = None

    # Current version of TMon
    version = '0.1-alpha'

    def __init__(self, args, config):
        if args.debug:
            log(LOG_ENV_SETUP, ['threatmonitor.ThreatMonitor'], 'debug')
        self.update_interval = args.interval
        self.config = config
        self.debug = args.debug

        self.banner()

        print
        stdout('[*] Initializing... Please wait as this can take some time...')
        stdout('[+] To follow the process please tail the log file')

        if self.debug:
            debug(LOG_LOADING_CLASS, ['DShield'])
        self.isc = dshield.DShield(config, self.debug)

    def monitor(self):

        log(LOG_INITIALIZE, ['monitor session'])
        while True:
            try:
                self.last_update = datetime.datetime.now()
                diff = datetime.timedelta(0, self.update_interval)
                self.next_update = self.last_update + diff
                self.last_update = str(self.last_update).split('.')[0]
                self.next_update = str(self.next_update).split('.')[0]
                # Update threat data
                self.update_dshield_data()

                self.update_interface()
                sleep(self.update_interval)

            except KeyboardInterrupt:
                log(LOG_USER_CANCELED_PROCESS)
                exit(0)

    def update_dshield_data(self):
        log(LOG_RESETTING, ['failure state'])
        self.isc.failure = False

        log(LOG_FETCH_DATA, ['top attacked ports'])
        self.isc.get_threat_level()

        log(LOG_FETCH_DATA, ['top attacked ports'])
        self.isc.get_top_ports()

        log(LOG_FETCH_DATA, ['unique sources'])
        self.isc.get_sources()

        log(LOG_FETCH_DATA, ['attacking countries'])
        self.isc.get_attacking_countries()

        log(LOG_FETCH_DATA, ['top 20 attacking sources'])
        self.isc.get_attacking_sources(20)

    def update_interface(self):
        self.banner()
        width = self.get_terminal_width()
        print
        stdout('[+] Last update: {0}', [self.last_update])
        stdout('[+] Next update: {0}', [self.next_update])

        if self.isc.failure is True:
            print

            error(ERROR_DETECTED)

        print
        stdout(IFACE_THREAT_LEVEL_TITLE)
        dshield_level = colored(self.isc.threat_level, self.isc.threat_level)
        stdout(IFACE_THREAT_DSHIELD_LEVEL, [dshield_level])
        print
        attrs = {'color': 'yellow', 'attrs':['reverse', 'bold']}
        stdout(IFACE_HEADER_TOP_TEN.ljust((width - 64) + 13), [
            'Top 10 ports', 'Top 10 attackers'], attrs)
        stdout(IFACE_TOP_TEN_COLUMNS, [
            'Port', 'Records', 'Service', 'Country', 'Attacks'])
        print "{0:-<46}+{1:-<{2}}".format('-', '-', (width - 47))
        ports = self.isc.top_ports
        countries = self.isc.attacking_countries

        for x in range(0, 9):
            port = ports[x][0].ljust(7)
            port_attacks = str(ports[x][1]).ljust(10)
            service = get_default_port_service(int(ports[x][0]))
            service = service.ljust(26)
            country = countries[x][0].ljust(23)
            country_attacks = countries[x][1]
            stdout(IFACE_PORTS_AND_COUNTRIES, [
                port, port_attacks, service, country, country_attacks])

        print
        attrs = {'color': 'yellow', 'attrs':['reverse', 'bold']}
        stdout(IFACE_HEADER_TOP_SOURCES.ljust(width), attrs=attrs)
        stdout(IFACE_TOP_SOURCES_COLUMNS, [
            'Source', 'Country', 'Attacks', 'First seen', 'Last seen'])
        print "".ljust(width, '-')

        if self.isc.attacking_sources is None:
            print colored('Unable to successfully fetch additional information about unique attacking sources', 'red')
        else:
            for ip, country, attacks, firstseen, lastseen in self.isc.attacking_sources:
                ip = ip.ljust(18)
                country = country.ljust(19)
                attacks = str(attacks).ljust(10)
                firstseen = firstseen.ljust(15)
                lastseen = lastseen
                stdout(IFACE_SOURCES, [
                    ip, country, attacks, firstseen, lastseen])

        print "".ljust(width, '-')

        pass

    def clearScreen(self):
        sys.stderr.write("\x1b[2J\x1b[H")

    def get_terminal_size(self, fd=1):
        try:
            hw = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ, '1234'))
        except:
            try:
                hw = (os.environ['LINES'], os.environ['COLUMNS'])
            except:
                hw = (25, 80)

        return hw

    def get_terminal_width(self, fd=1):
        if os.isatty(fd):
            width = self.get_terminal_size(fd)[1]
        else:
            width = 999

        return width

    def banner(self):
        self.clearScreen()
        width = self.get_terminal_width()
        print "-"*width
        print "- Internet Threat Monitor v%s (by Ole Aass)" % (self.version)
        print "-"*width
