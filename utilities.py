#!/usr/bin/env python

import datetime
import sys
from termcolor import colored


def log(message, replace=[], severity='log'):
    severity_levels = ['debug', 'warning', 'error', 'fatal', 'log']
    if severity not in severity_levels:
        severity = 'UNKNOWN'
    timestamp = str(datetime.datetime.now()).split('.')[0]
    message = message.format(*replace)
    logmessage = '[%s] [%s] %s\n' % (timestamp, severity.upper(), message)
    logfile = open('log.txt', 'a')
    logfile.write(logmessage)
    logfile.close()


def debug(message, replace=[]):
    log(message, replace, 'debug')


def warning(message, replace=[]):
    log(message, replace, 'warning')


def error(message, replace=[]):
    log(message, replace, 'error')
    output = message.format(*replace)
    stdout('[!] Error: {0}', [output], 'red')


def fatal(message, replace=[]):
    log(message, replace, 'fatal')
    output = message.format(*replace)

    exit(0)


def flush_log():
    logfile = open('log.txt', 'w')
    logfile.close()


def get_default_port_service(port):
    services = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        67: 'BOOTP / DHCP',
        80: 'HTTP',
        137: 'NetBIOS Name Service',
        138: 'NetBIOS Datagram Service',
        139: 'NetBIOS Session Service',
        161: 'SNMP',
        443: 'HTTPS',
        445: 'Active Directory / SMB',
        514: 'Shell / Syslog',
        1433: 'MSSQL Server',
        1434: 'MSSQL Monitor',
        1443: 'MSSQL',
        3306: 'MySQL',
        3389: 'RDP / WBT',
        5060: 'SIP',
        5061: 'SIPTLS',
        5900: 'RFP / VNC',
        8080: 'HTTP',
        9200: 'ElasticSearch'
    }

    try:
        return services[port]
    except:
        return 'N/A'


def stdout(message, replace=None, attrs={'color': None, 'attrs': None}):

    if replace is not None:
        output = '%s' % (message.format(*replace))
    else:
        output = '%s' % (message)

    if attrs['color'] is not None:
        if attrs['attrs'] is not None:
            output = colored(output, attrs['color'], attrs=attrs['attrs'])
        else:
            outpuy = colored(output, attrs['color'])

    print output