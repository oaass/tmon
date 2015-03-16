#!/usr/bin/env python

import requests
import dshield
import datetime
import os
import fcntl
import termios
import struct
import sys
from termcolor import colored
from time import sleep
from utilities import *

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
                self.next_update = self.last_update + datetime.timedelta(0, self.update_interval)
                self.last_update = str(self.last_update).split('.')[0]
                self.next_update = str(self.next_update).split('.')[0]
                # Update threat data
                self.updateDShieldData()

                self.updateInterface()
                sleep(self.update_interval)

            except KeyboardInterrupt:
                log('User terminated session')
                exit(0)

    def getDefaultPortService(self, port):
        if self.debug:
            log("Attempting to find default service for port '%s'"%(port), 'debug')
        try:
            service = getDefaultPortService(port)
            if self.debug:
                log("Default service for port '%s' is '%s'"%(port, service), 'debug')
        except:
            service = 'N/A'
            if self.debug:
                log("Unable to find default service for port '%s'"%(port), 'debug')
        return service

    def snapshot(self):
        pass

    def updateDShieldData(self):
        if self.debug:
            log('Resetting failure state', 'debug')
        self.isc.failure = False
        log('Reading threat level from DSheild')
        self.isc.getThreatLevel()
        log('Reading top attacked ports')
        self.isc.getTopPorts()
        log('Reading unique sources')
        self.isc.getSources()
        log('Reading attacking countries')
        self.isc.getAttackingCountries()
        log('Reading top 20 attacking sources')
        self.isc.getAttackingSources(20)

    def updateInterface(self):
        self.banner()
        width = self.get_terminal_width()
        print
        print "[+] Last update: %s"%(self.last_update)
        print "[+] Next update: %s"%(self.next_update)

        if self.isc.failure is True:
            print
            print colored("[!] Errors was detected. Errors can be found in the log.", "yellow")

        print
        print "[+] Current threat levels"
        print "    [+] DShield ISC: %s"%(colored(self.isc.threat_level, self.isc.threat_level))
        print
        print colored("Top 10 targeted ports                         | Top 10 attacking countries".ljust(width), 'yellow', attrs=['reverse', 'bold'])
        print "Port    Records    Service                    | Country                 Attacks"
        print "----------------------------------------------+".ljust(width, '-')

        ports = self.isc.top_ports
        countries = self.isc.attacking_countries

        for x in range(0, 9):
            port = ports[x][0]
            attacks = ports[x][1]
            service = self.getDefaultPortService(int(ports[x][0]))
            country = countries[x][0]
            attacks = countries[x][1]
            print "%s %s %s | %s %s"%(port.ljust(7), str(attacks).ljust(10), service.ljust(26), country.ljust(23), attacks)

        print
        print colored("Top 20 attacking sources".ljust(width), 'yellow', attrs=['reverse', 'bold'])
        print "Source          | ASName                                | Country             | Attacks | First seen | Last seen"
        print "----------------+---------------------------------------+---------------------+---------+------------+".ljust(width, '-')

        if self.isc.attacking_sources is None:
            print colored('Unable to successfully fetch additional information about unique attacking sources', 'red')
        else:
            for ip, asname, country, attacks, firstseen, lastseen in self.isc.attacking_sources:
                print "%s | %s | %s | %s  | %s | %s"%(ip.ljust(15), asname.ljust(37), country.ljust(19), str(attacks).ljust(6), firstseen.ljust(10), lastseen.ljust(10))

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
        print "- Internet Threat Monitor v%s (by Ole Aass)"%(self.version)
        print "-"*width