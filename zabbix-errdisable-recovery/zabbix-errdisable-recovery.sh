#!/bin/bash

cd /etc/zabbix/alertscripts/zabbix-errdisable-recovery
/usr/local/bin/ansible-playbook clear-portsecurity.yml --vault-password-file=vault/vault_password -e interface=$1 -i $2,
