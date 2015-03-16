#!/usr/bin/env python

import datetime

def log(message, severity = 'log'):
    severity_levels = ['debug', 'warning', 'error', 'fatal', 'log']
    if not severity in severity_levels:
        severity = 'UNKNOWN'
    timestamp = str(datetime.datetime.now()).split('.')[0]
    message = '[%s] [%s] %s\n'%(timestamp, severity.upper(), message)
    logfile = open('log.txt', 'a')
    logfile.write(message)
    logfile.close()
    if severity is 'fatal':
        log('Terminating program')

def flushlog():
    logfile = open('log.txt', 'w')
    logfile.close()

def error(message, type):
    timestamp = str(datetime.datetime.now()).split('.')[0]
    fmt = "[!!] Fatal Error: %s" if type is 'fatal' else "[!] Error: %s"
    print fmt%(message)
    if type is 'fatal':
        exit(0)

def getDefaultPortService(port):
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