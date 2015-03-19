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
from utilities import get_default_port_service


class ThreatMonitor():

    # Seconds between each update
    update_interval = None

    # Configuration
    config = None

    # Current version of TMon
    version = '0.1-alpha'

    def __init__(self, args, config):
        if args.debug:
            log('Setting up environment in threatmonitor.ThreatMonitor', 'debug')
        self.update_interval = args.interval
        self.config = config
        self.debug = args.debug

        self.banner()

        print
        print "[+] Fetching data... Please wait as this can take some time..."
        print "[+] To follow the process please tail the log file"

        if self.debug:
            log('Loading DShield API class', 'debug')

        self.isc = dshield.DShield(config, self.debug)

    def monitor(self):

        log('Initializing monitor session')
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
                log('User terminated session')
                exit(0)

    def update_dshield_data(self):
        if self.debug:
            log('Resetting failure state', 'debug')
        self.isc.failure = False
        log('Reading threat level from DSheild')
        self.isc.get_threat_level()
        log('Reading top attacked ports')
        self.isc.get_top_ports()
        log('Reading unique sources')
        self.isc.get_sources()
        log('Reading attacking countries')
        self.isc.get_attacking_countries()
        log('Reading top 20 attacking sources')
        self.isc.get_attacking_sources(20)

    def update_interface(self):
        self.banner()
        width = self.get_terminal_width()
        print
        print "[+] Last update: %s" % (self.last_update)
        print "[+] Next update: %s" % (self.next_update)

        if self.isc.failure is True:
            print
            print colored("[!] Errors was detected. Errors can be found in the log.", "yellow")

        print
        print "[+] Current threat levels"
        print "    [+] DShield ISC: %s" % (colored(self.isc.threat_level, self.isc.threat_level))
        print
        print colored("Top 10 targeted ports                         | Top 10 attacking countries".ljust(width), 'yellow', attrs=['reverse', 'bold'])
        print "Port    Records    Service                    | Country                 Attacks"
        print "----------------------------------------------+".ljust(width, '-')

        ports = self.isc.top_ports
        countries = self.isc.attacking_countries

        for x in range(0, 9):
            port = ports[x][0]
            attacks = ports[x][1]
            service = get_default_port_service(int(ports[x][0]))
            country = countries[x][0]
            attacks = countries[x][1]
            print "%s %s %s | %s %s" % (port.ljust(7), str(attacks).ljust(10), service.ljust(26), country.ljust(23), attacks)

        print
        print colored("Top 20 attacking sources".ljust(width), 'yellow', attrs=['reverse', 'bold'])
        print "Source          | ASName                                | Country             | Attacks | First seen | Last seen"
        print "----------------+---------------------------------------+---------------------+---------+------------+".ljust(width, '-')

        if self.isc.attacking_sources is None:
            print colored('Unable to successfully fetch additional information about unique attacking sources', 'red')
        else:
            for ip, asname, country, attacks, firstseen, lastseen in self.isc.attacking_sources:
                print "%s | %s | %s | %s  | %s | %s" % (ip.ljust(15), asname.ljust(37), country.ljust(19), str(attacks).ljust(6), firstseen.ljust(10), lastseen.ljust(10))

        print "----------------+---------------------------------------+---------------------+---------+------------+".ljust(width, '-')

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
