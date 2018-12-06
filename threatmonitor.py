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
    version = '1.0'

    def __init__(self, args, config):
        if args.debug:
            log('Setting up environment in threatmonitor.ThreatMonitor', 'debug')
        self.update_interval = args.interval
        self.config = config
        self.debug = args.debug
        self.args = args

        self.banner(self.args.status_only)

        if self.args.status_only is False:

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
        
        if self.args.status_only is False:
            log('Reading top %d attacked ports'%(self.args.max_ports))
            self.isc.getTopPorts(self.args.max_ports)
            log('Reading unique sources')
            self.isc.getSources()
            log('Reading top %d attacking countries'%(self.args.max_countries))
            self.isc.getAttackingCountries(self.args.max_countries)
            if self.args.max_ips > 0:
                log('Reading top %d attacking sources'%(self.args.max_ips))
                self.isc.getAttackingSources(self.args.max_ips)

    def updateInterface(self):
        width = self.get_terminal_width()
        if self.args.status_only is False:
            self.banner(self.args.status_only)
            print
            print "[+] Last update: %s"%(self.last_update)
            print "[+] Next update: %s"%(self.next_update)

            if self.isc.failure is True:
                print
                print colored("[!] Errors was detected. Details can be found in the log.", "yellow")

            print
        
        print "[+] Current threat levels"
        print "    [+] DShield ISC: %s"%(colored(self.isc.threat_level, self.isc.threat_level))

        if self.args.status_only:
            exit(0)

        print
        print colored("Top %d targeted ports                         | Top %d attacking countries".ljust(width)%(self.args.max_ports, self.args.max_countries), 'yellow', attrs=['reverse', 'bold'])
        print "Port    Attacks    Service                    | Country                 Attacks"
        print "----------------------------------------------+".ljust(width, '-')

        ports = self.isc.top_ports
        countries = self.isc.attacking_countries

        for x in range(0, self.args.max_ports):
            if x < self.args.max_ports:
                port = ports[x][0]
                records = ports[x][1]
                service = self.getDefaultPortService(int(ports[x][0]))
            else:
                port = ''
                records = ''
                service = ''

            try:
                if countries[x] is not None:
                    if x < self.args.max_countries:
                        country = countries[x][0]
                        attacks = countries[x][1]
                    else:
                        country = ''
                        attacks = ''
            except:
                country = ''
                attacks = ''

            print "%s %s %s | %s %s"%(str(port).ljust(7), str(records).ljust(10), service.ljust(26), country.ljust(23), attacks)

        if self.args.max_ips == 0:
            print "----------------------------------------------+".ljust(width, '-')
        else:
            print
            print colored("Top %d attacking IPs".ljust(width)%(self.args.max_ips), 'yellow', attrs=['reverse', 'bold'])
            print "Source          | ASName                                | Country             | Attacks | First seen | Last seen"
            print "----------------+---------------------------------------+---------------------+---------+------------+".ljust(width, '-')

            if self.isc.attacking_sources is None:
                print colored('Unable to successfully fetch additional information about unique attacking IPs', 'red')
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
    def banner(self, simple):
        if simple:
            print
            print "Internet Threat Monitor v%s"%(self.version)
            print "by Ole Aass"
            print
        else:
            self.clearScreen()
            width = self.get_terminal_width()
            print "-"*width
            print "- Internet Threat Monitor v%s"%(self.version)
            print "- by Ole Aass"
            print "-"*width
