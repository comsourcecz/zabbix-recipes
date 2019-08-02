#!/usr/bin/python
"""
zabbix discovery script that discovers all the qos queues and 
qos enabled physical interfaces on Juniper devices

the script accepts 2 arguments: hostname and community
and returns a structured data (JSON) back to a zabbix server

1. get Qos Interfaces  (ifList[])

> show snmp mib walk 1.3.6.1.4.1.2636.3.15.5.1.2   
jnxCosIfstatFlags.508 = 80 
jnxCosIfstatFlags.509 = 80 
jnxCosIfstatFlags.510 = 80 
jnxCosIfstatFlags.511 = 80 
jnxCosIfstatFlags.513 = 80 
jnxCosIfstatFlags.519 = 80 
jnxCosIfstatFlags.532 = 80 

2. get ifNames for each ifIndex (580, 509, ... 532)

> show snmp mib get ifName.508 
ifName.508    = ge-0/0/0

> show snmp mib get ifName.509    
ifName.509    = ge-0/0/0.0

3. strip off of *.0 interfaces (we need physical interfaces only)
4. make list of dictionaries ifListDict[]
ifListDict = [ {"ifName": "ge-0/0/0", "ifIndex": 508}, {"ifName": "ge-0/0/1", "ifIndex": 510}]

5. get Qos Queues (QlistDict[])
[ {"qName": voip", "qIndex": 5}, {"qName": video", "qIndex": 4}]

> show snmp mib walk 1.3.6.1.4.1.2636.3.15.3.1.2                   
jnxCosFcIdToFcName.0 = best-effort
jnxCosFcIdToFcName.1 = business-app
jnxCosFcIdToFcName.2 = wsus
jnxCosFcIdToFcName.3 = network-control
jnxCosFcIdToFcName.4 = video
jnxCosFcIdToFcName.5 = voip

QlistDict = [ {"qName": voip", "qIndex": 5}, {"qName": video", "qIndex": 4}]

6. create new list of dicts like that:

[{'ifName': 'ge-0/0/0',  'ifIndex': 508,
  'qName': 'voip',  'qIndex': 5,  'Index': 1},
 {'ifName': 'ge-0/0/0',  'ifIndex': 508,
  'qName': 'video',  'qIndex': 4,  'Index': 2},
 {'ifName': 'ge-0/0/1',  'ifIndex': 510,
  'qName': 'voip',  'qIndex': 5,  'Index': 3},
 {'ifName': 'ge-0/0/1',  'ifIndex': 510,
  'qName': 'video',  'qIndex': 4,  'Index': 4}]

7. and finally return that object as JSON to zabbix
print (json.dumps({"data": qlist}, indent=4))
"""

import sys
from pysnmp.hlapi import *
import json

def snmpwalk(oid, hostname, community):
    l = []
    varBind = nextCmd(SnmpEngine(), CommunityData(community), UdpTransportTarget((hostname, 161)),
        ContextData(), ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False)

    # do snmmpwalk and collect list of tupples (snmpindex, snmpvalue) 
    for res in varBind:        
        l.append((str(res[3][0][0][-1]), (str(res[3][0][1]))))
    return l

def find_ifDesc_from_ifIndex(hostname, ifIndex, community="publices"):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData(community),
               UdpTransportTarget((hostname, 161)),
               ContextData(),
               ObjectType(ObjectIdentity('IF-MIB', 'ifDescr', ifIndex)))
    )

    if errorIndication:
        logging.error(errorIndication)
    elif errorStatus:
        logging.error('%s at %s', errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex) - 1][0] or '?')
        exit(1)
    else:
        ifDescr = varBinds[0][1].prettyPrint()
        return ifDescr

eRR = '{ data: ["Error parsing arguments"]}\n'
jnxCosIfstatFlags = "1.3.6.1.4.1.2636.3.15.5.1.2"
ifName = "1.3.6.1.2.1.31.1.1.1.1"
jnxCosFcIdToFcName = "1.3.6.1.4.1.2636.3.15.3.1.2"

if len(sys.argv)!=3:
    sys.stderr.write(eRR)
    exit()

hostname = sys.argv[1]
community=sys.argv[2]

# 1.
iflist = snmpwalk(jnxCosIfstatFlags, hostname, community)

# 2.
ltmp = [ (a[0],str(find_ifDesc_from_ifIndex(hostname, a[0], community))) for a in iflist ]

# 3. 
import re
pattern = re.compile("[gf]e-\d+/\d+/\d+$")
ifList = [ a for a in ltmp if pattern.match(a[1]) ]

# 4.
fields = ["{#IFINDEX}", "{#IFNAME}"]
ifListDict = [ dict(zip(fields, i)) for i in ifList ]

# 5.
qlist = snmpwalk(jnxCosFcIdToFcName, hostname, community)
fields = ["{#QINDEX}", "{#QNAME}"]
QlistDict = [ dict(zip(fields, i)) for i in qlist ]

# 6.
qoslist=[]
index=1
for d1 in ifListDict:
    for d2 in QlistDict:
        d = {}
        d = d1.copy()
        d.update(d2)
        d["{#INDEX}"]=index        
        qoslist.append(d)
        index+=1

# 7.
print (json.dumps({"data": qoslist}, indent=4))
