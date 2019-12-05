import sys
import netaddr

mac = None
vault_file = "defaults/creds.yml"
vault_password_file = "vault/vault_password"
commands = []

# sys.argv

if len(sys.argv) == 3 :
    ifname = sys.argv[1]
    hostname = sys.argv[2]    
elif len(sys.argv) == 4 :
    ifname = sys.argv[1]
    mac_str = sys.argv[2]
    hostname = sys.argv[3]

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

# data = { 'user': val1, 'pass': val2}    

# napalm
import napalm
driver = napalm.get_network_driver("ios")

with driver(hostname, vaultdata['user'], vaultdata['pass']) as device:
    device.open()
    res = device.cli(commands)                                                                                                   
    print(res)                                                                                                                   
