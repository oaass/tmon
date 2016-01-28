#!/usr/bin/env python

import json
import requests
import pygeoip
import ConfigParser
from IPy import IP
from utilities import *

class DShield():

    # DShield API URLs
    URL_THREAT_LEVEL   = 'https://isc.sans.edu/api/infocon?json'
    URL_TOP_PORTS      = 'https://isc.sans.edu/api/topports/records/%d?json'
    URL_SOURCES        = 'https://isc.sans.edu/api/sources/%s/%d?json'
    URL_IP_DETAILS     = 'https://isc.sans.edu/api/ip/%s?json'

    # Current DShield threat level
    threat_level   = None

    # List of top attacked ports
    top_ports      = None

    # List of sources
    sources        = None

    # List of attacking countries
    attacking_countries = None

    # List of attacking sources
    attacking_sources = None

    # If any of the tasks fails this will switch to True
    failure        = False

    # Instance of pygeoip
    geo = None

    def __init__(self, config, debug):
        if debug:
            log('Setting up envirnment in dshield.DShield', 'debug')

        self.debug = debug

        if self.debug:
            log('Loading configuration for geo location', 'debug')
        try:
            geofile = config.get('geolocation', 'filepath')
        except KeyboardInterrupt:
            log('User terminated session')
            exit(0)
        except ConfigParser.NoOptionError, e:
            log('Configuration: %s'%(e), 'fatal')
            error('%s'%(e), 'fatal')
        except Exception, e:
            log('Unexpected error occured when trying to read geolocation filepath configurations.', 'error')
            log('%s'%(e), 'fatal')
            error('%s'%(e), 'fatal')

        if self.debug:
            log("Initializing pygeoip.GeoIP with '%s'"%(geofile), 'debug')

        try:
            self.geo = pygeoip.GeoIP(geofile)
        except KeyboardInterrupt:
            log('User terminated session')
            exit(0)
        except IOError, e:
            message = str(e).replace('[Errno 2] ', '')
            log('%s'%(message), 'fatal')
            error('%s'%(message), 'fatal')
        except Exception, e:
            log('Unexpected error occured when trying to initialize pygeoip.GeoIP with %s'%(geofile), 'error')
            log('%s'%(e), 'fatal')
            error('%s'%(e), 'fatal')

    def getThreatLevel(self):
        if self.debug:
            log('Trying to read current DShield threat level', 'debug')
        try:

            if self.debug:
                log('Requesting URL %s'%(self.URL_THREAT_LEVEL), 'debug')

            response = requests.get(self.URL_THREAT_LEVEL)
            self.threat_level = json.loads(response.text)['status']
            log('Successfully read threat level')
            return self.threat_level
        except KeyboardInterrupt:
            log('User terminated session')
            exit(0)
        except Exception, e:
            log('Failed reading threat level')
            log("%s in 'DShield.getThreatLevel()'"%(e), 'error')
            self.failure = True

    def getTopPorts(self, limit=10):
        if self.debug:
            log('Trying to read top %d attacked ports'%(limit), 'debug')
        try:

            if self.debug:
                log('Requesting URL %s'%(self.URL_TOP_PORTS%(limit)), 'debug')

            response = requests.get(self.URL_TOP_PORTS%(limit))
            data = json.loads(response.text)

            self.top_ports = []
            for x in range(0, limit-1):
                x = str(x)
                port = data[x]['targetport']
                attacks = data[x]['records']
                self.top_ports.append((port, attacks))

            log('Successfully read top attacked ports')
            return self.top_ports
        except KeyboardInterrupt:
            log("User terminated session")
            exit(0)
        except Exception, e:
            log('Failed reading top attacked ports')
            log("%s in 'DShield.getTopPorts()'"%(e), 'error')
            self.failure = True

    def getSources(self, column='attacks', limit=100):
        if self.debug:
            log('Trying to read attacking sources', 'debug')
        try:

            if self.debug:
                log('Requesting URL %s'%(self.URL_SOURCES%(column, limit)), 'debug')

            response = requests.get(self.URL_SOURCES%(column, limit), headers={'User-Agent': 'Python Threat Monitor'})
            obj = json.loads(response.text)
            
            self.sources = []
            for id in range(0, len(obj)):
                try:
                    ip = self.sanitizeIp(obj[id]['ip'])
                    if not IP(ip).iptype() is 'PUBLIC':
                        log("Detected '%s' as a possible local IP. Manual inspection might be required"%(ip), 'warning')
                    country = self.geo.record_by_name(ip)['country_name']
                    attacks = int(obj[id]['attacks'])
                    count = int(obj[id]['count'])
                    firstseen = obj[id]['firstseen']
                    lastseen = obj[id]['lastseen']
                    self.sources.append((ip,country,attacks,count,firstseen,lastseen))
                except KeyboardInterrupt:
                    log("User terminated session")
                    exit(0)
                except TypeError, e:
                    country = ''
                except Exception, e:
                    log('Failed reading an attacking source')
                    log("%s in 'DShield.getSources' (#3)"%(e), 'error')
                    self.failure = True
                    exit(0)

            log('Successfully read attacking sources')
            return self.sources
        except KeyboardInterrupt:
            log('User terminated session')
            exit(0)
        except Exception, e:
            log('Failed reading sources')
            log("%s in 'DShield.getSources()' (#4)"%(e), 'error')
            self.failure = True

    def getAttackingCountries(self, limit=10):
        if self.debug:
            log('Trying to read attacking countries', 'debug')
        try:
            if self.sources is None:
                self.getSources()

            data = {}
            for ip, country, attacks, count, firstseen, lastseen  in self.sources:
                try:
                    data[country] += attacks
                except:
                    data[country] = attacks

            self.attacking_countries = sorted(data.items(), key=lambda x:x[1], reverse=True)
            return self.attacking_countries

        except KeyboardInterrupt:
            log('User terminated session')
            exit(0)
        except Exception, e:
            log('Failed reading attacking countries')
            log("%s in 'DHsield.getAttackingCountries"%(e), 'error')
            self.failure = True

    def getAttackingSources(self, limit=10):
        if self.debug:
            log('Trying to read additional information about attacking sources')
        try:
            if self.sources is None:
                self.getSources()

            data = []
            for x in range(0, limit):
                source = self.sources[x]
                ip = source[0]
                asname = self.getExtendedSourceInfo(ip, 'asname')
                if asname is None:
                    asname = 'N/A'
                else:
                    asname = asname if len(asname) < 35 else asname[:32] + '...'

                country = source[1] if len(source[1]) < 19 else source[1][:15] + '...'
                attacks = int(source[2])
                firstseen = source[4]
                lastseen = source[5]
                data.append((ip, asname.strip(), country, attacks, firstseen, lastseen))

            log('Successfully read attacking sources')
            self.attacking_sources = sorted(data, key=lambda x:x[3], reverse=True)
            return self.attacking_sources
        except KeyboardInterrupt:
            log('User terminated session')
            exit(0)
        except Exception, e:
            log('Failed getting attacking sources')
            log("%s in 'DShield.getAttackingSources'"%(e), 'error')
            self.failure = True

    def sanitizeIp(self, ip):
        try:
            parts = ip.split('.')
            sanitized = []
            for part in parts:
                sanitized.append(str(int(part)))

            sanitized = '.'.join(sanitized)
            return sanitized
        except KeyboardInterrupt:
            log('User terminated session')
            exit(0)
        except Exception, e:
            log("Unexpected exception occured when trying to sanitize IP '%s'"%(ip), 'warning')
            return ip

    def getExtendedSourceInfo(self, source, field = None):
        try:
            log("Fetching extended information about '%s'"%(source), 'log')

            if self.debug:
                log('Requesting URL %s'%(self.URL_IP_DETAILS%(source)), 'debug')

            response = requests.get(self.URL_IP_DETAILS%(source))
            obj = json.loads(response.text)

            if not field is None:
                log("Successfully read '%s' for '%s'"%(field, source))
            else:
                log("Successfully read extended source info for '%s'"%(source))
            return obj['ip'][field] if not field is None else obj
        except KeyboardInterrupt:
            log('User terminated session')
            exit(0)
        except Exception, e:
            log('Failed getting extended source info')
            log("%s in 'DShield.getExtendedSourceInfo'"%(e), 'error')
            self.failure = True
