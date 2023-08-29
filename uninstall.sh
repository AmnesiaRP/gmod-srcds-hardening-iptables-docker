#!/bin/bash

delete_rules () {
    TABLE=$1
    iptables -t $TABLE -L -v -n --line-numbers | grep "/\* srcds-hardening \*/" | sort -nr | awk "{print \"iptables -t $TABLE -D PREROUTING \"\$1}"
}

delete_rules raw
delete_rules mangle


echo -e "DDoS Netfilter is \033[31mdisabled\033[0m"

echo -e "\033[32mUninstall complete\033[0m"
