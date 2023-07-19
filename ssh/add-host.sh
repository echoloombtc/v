#!/bin/bash
# //====================================================
# //	System Request:Debian 9+/Ubuntu 18.04+/20+
# //	Author:	kenDevXD
# //	Dscription: Xray Menu Management
# //	email: merahjambo@gmail.com
# //  telegram: https://t.me/Baung2012
# //====================================================
# // font color configuration | TARAP KUHING AUTOSCRIPT
ateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
#########################

cekray=`cat /root/log-install.txt | grep -ow "XRAY" | sort | uniq`
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHT='\033[0;37m'
Font="\033[0m"
gray="\e[1;30m"
total_ram=$(grep "MemTotal: " /proc/meminfo | awk '{ print $2}')
totalram=$(($total_ram / 1024))
MYIP=$(curl -sS ipv4.icanhazip.com)
LAST_DOMAIN="$(cat /etc/xray/domain)"
NS="$(cat /etc/xray/dns)"
red() { echo -e "\\033[32;1m${*}\\033[0m"; }

clear
echo -e "\033[0;33m   ┌──────────────────────────────────────────┐\033[0m"
echo -e "\033[0;33m   │\033[0m            \033[0;32mCHANGE DOMAIN VPS\033[0m             \033[0;33m|\033[0m"
echo -e "\033[0;33m   └──────────────────────────────────────────┘\033[0m"
echo -e "     ${RED}Autoscript Tarap Kuhing Tunneling (multi port)${NC}"
echo -e "${RED}Make sure the internet is smooth when installing the script${NC}"
echo -e "───────────────────────────────────────────────────────"
echo -e ""
echo -e "       ${GREEN}Hostname${NC}    :  $LAST_DOMAIN"
echo -e "       ${GREEN}Public IP${NC}   :  $MYIP"
echo -e "       ${GREEN}Total RAM${NC}   :  $totalram MB"
echo -e ""
echo -e "───────────────────────────────────────────────────────"
read -rp "Input ur Domain/Host : " -e domain
rm -rf /etc/xray/domain
rm -rf /etc/v2ray/domain
rm -rf /etc/xray/scdomain
rm -rf /etc/v2ray/scdomain
echo "$domain" > /root/domain
echo "$domain" > /etc/v2ray/domain
echo "$domain" > /etc/xray/domain
echo "$domain" > /etc/v2ray/scdomain
echo "$domain" > /etc/xray/scdomain
echo "IP=$domain" > /var/lib/ipvps.conf
certv2ray
