#!/usr/bin/python
"""
 Zabbix discovery junper rpm tests external script
 this script is intended to find RPM (Real test perfomance monitoring) owners and tests out of a juniper network devices

 the script accepts 2 arguments: hostname and community
 and returns a structured data back to a zabbix server

 first it does snmpwalk over jnxRpmResSumSent MIB Object
 from a device perspective it looks like this:

 user@ex2200> show snmp mib walk jnxRpmResSumSent ascii
 jnxRpmResSumSent."ISP1"."Test1".1 = 14
 jnxRpmResSumSent."ISP1"."Test1".2 = 15
 jnxRpmResSumSent."ISP1"."Test1".4 = 45614
 jnxRpmResSumSent."ISP2"."Test2".1 = 13
 jnxRpmResSumSent."ISP2"."Test2".2 = 15
 jnxRpmResSumSent."ISP2"."Test2".4 = 6073

 using jnxRpmResSumSent MIB Object we can find all existed tests. even those that are not performed successfully

 returned data are being structured to a form of a Zabbix discobery JSON
 { data: [
 {"{#RPMUUID}":"3.73.83.80.49.6.84.69.83.84.49", "{#RPMOWNER}":"ISP1", "{#RPMTEST}":"Test1" },
 {"{#RPMUUID}":"4.73.83.80.50.84.69.83.84.50", "{#RPMOWNER}":"ISP2", "{#RPMTEST}":"Test2" },
 ]}
"""

import sys
from pysnmp.hlapi import *
import json

def findsubstrings(s):
    la = s.split('.')
    lb = la[1:]

    if '6' in lb: # looking for a delimiter. 6 for EX or 8,10 for SRX
        i = lb.index('6')
    elif '8' in lb:
        i = lb.index('8')
    elif '10' in lb:
        i = lb.index('10')
    else:
        sys.stderr.write("delimiter nor 6 ot 10")
        exit(0)

    l1 = lb[:i]
    l2 = lb[i+1:]
    param2 = ''.join([chr(int(i)) for i in l1])
    param3 = ''.join([chr(int(i)) for i in l2])
    return param2, param3


eRR = '{ data: ["Error parsing arguments"]}\n'

if len(sys.argv)!=3:
    sys.stderr.write(eRR)
    exit()

hostname = sys.argv[1]
community=sys.argv[2]
jnxRpmResSumSent = "1.3.6.1.4.1.2636.3.50.1.2.1.2"
l = []

# init snmpwalk over jnxRpmResSumSent MIB Object
varBind = nextCmd(SnmpEngine(), CommunityData(community), UdpTransportTarget((hostname, 161)),
    ContextData(), ObjectType(ObjectIdentity(jnxRpmResSumSent)),
    lexicographicMode=False)

# do snmmpwalk and collect an rpm specific substring
for res in varBind:
    s = str(res[3][0][0])[len(jnxRpmResSumSent)+1:-2]
    l.append(s)

# lets make values inside the list l uniq
u = set(l)


jsonData=[]
for param1 in u:
    d={}
    param2, param3 = findsubstrings(param1)
    d["{#RPMUUID}"] = param1
    d["{#RPMOWNER}"] = param2
    d["{#RPMTEST}"] = param3
    jsonData.append(d)

print (json.dumps({"data": jsonData}, indent=4))












