import sys
import netaddr

path = "/etc/zabbix/alertscripts/zabbix-errdisable-recovery/"
vault_file = "defaults/creds.yml"
vault_password_file = "vault/vault_password"

vault_file = path + vault_file
vault_password_file = path + vault_password_file
log_file = path + "errdisable-recovery.log"

mac = None
commands = []

# sys.argv

if len(sys.argv) == 4 :
    ifname = sys.argv[1]
    hostname = sys.argv[2]    
    eventid = sys.argv[3]
elif len(sys.argv) == 5 :
    ifname = sys.argv[1]
    mac_str = sys.argv[2]
    hostname = sys.argv[3]
    eventid = sys.argv[4]

    mac_str = netaddr.EUI(sys.argv[2])
    mac_str.dialect = netaddr.mac_cisco
    mac = str(mac_str)
else:
    msg = "Missing or invalid arguments"
    raise ValueError(msg)

command = "clear port-security sticky interface {}".format(ifname)
commands.append(command)

if mac:
    command = "clear port-security sticky address {}".format(mac)
    commands.append(command)

# vault
import os
from ansible_vault import Vault

if not (os.path.exists(vault_file) and os.path.isfile(vault_file)):
    msg = "Missing or invalid vault file {0}".format(vault_file)
    raise ValueError(msg)
if not (os.path.exists(vault_password_file) and os.path.isfile(vault_password_file)):
    msg = "Missing or invalid vault file {0}".format(vault_file)
    raise ValueError(msg)

with open(vault_password_file, "r") as fp:
    password = fp.readline().strip()   
    vault = Vault(password)
    vaultdata = vault.load(open(vault_file).read())

# vaultdata = { 'user': val1, 'pass': val2, 'zabbix_url': val3, 'zabbix_user': val4, 'zabbix_passwd': val5}    

# execute cli commands on a cisco switch using NAPALM
import napalm
from datetime import datetime
driver = napalm.get_network_driver("ios")

with driver(hostname, vaultdata['user'], vaultdata['pass']) as device:
    device.open()
    res = device.cli(commands)
    with open(log_file, "a+") as fl:
        logstr = str(datetime.now()) + ' - the following commands were executed on a {}:\n\t - '.format(hostname) + '\n\t - '.join(commands) + '\n'
        fl.write(logstr)

        # close the zabbix event using zabbixAPI 
        from zabbix.api import ZabbixAPI, ZabbixAPIException
        with ZabbixAPI(url=vaultdata['zabbix_url'], user=vaultdata['zabbix_user'], password=vaultdata['zabbix_passwd']) as zapi:                
            try:
                result = zapi.do_request('event.acknowledge', 
                    {
                        "eventids": eventid,
                        "message": "PortSecurity Problem Resolved.",
                        "action": 1
                    })
                if result['id'] == '1':
                    fl.write("Zabbix event has been closed successfully")
            except ZabbixAPIException as err:
                fl.write(err)                                                                                                            
