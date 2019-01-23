#!/bin/bash

cd /etc/zabbix/alertscripts/zabbix-errdisable-recovery

#zabbix is calling the script with either 3 or 2 args
# it can be "FastEthernet0/1 00:08:5D:51:DA catalyst100"
# or maybe  "FastEthernet0/1 catalyst100"
# $# bash variable returns the number of args

if [ $# -eq 3 ]
then
# call ansible playbook with 3 args
/usr/local/bin/ansible-playbook clear-portsecurity.yml --vault-password-file=vault/vault_password -e interface=$1 -e mac=$2 -i $3,
elif [ $# -eq 2 ]
# call ansible playbook with 2 args
then
/usr/local/bin/ansible-playbook clear-portsecurity.yml --vault-password-file=vault/vault_password -e interface=$1 -i $2,
fi
