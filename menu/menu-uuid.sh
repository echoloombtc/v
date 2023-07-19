#!/bin/bash
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
###########- COLOR CODE -##############
colornow=$(cat /etc/kenDevXD/theme/color.conf)
NC="\e[0m"
RED="\033[0;31m"
COLOR1="$(cat /etc/kenDevXD/theme/$colornow | grep -w "TEXT" | cut -d: -f2|sed 's/ //g')"
COLBG1="$(cat /etc/kenDevXD/theme/$colornow | grep -w "BG" | cut -d: -f2|sed 's/ //g')"
 WH='\033[1;37m'
###########- END COLOR CODE -##########

BURIQ () {
    curl -sS https://raw.githubusercontent.com/kenDevXD/ip/main/vps > /root/tmp
    data=( `cat /root/tmp | grep -E "^### " | awk '{print $2}'` )
    for user in "${data[@]}"
    do
    exp=( `grep -E "^### $user" "/root/tmp" | awk '{print $3}'` )
    d1=(`date -d "$exp" +%s`)
    d2=(`date -d "$biji" +%s`)
    exp2=$(( (d1 - d2) / 86400 ))
    if [[ "$exp2" -le "0" ]]; then
    echo $user > /etc/.$user.ini
    else
    rm -f /etc/.$user.ini > /dev/null 2>&1
    fi
    done
    rm -f /root/tmp
}

MYIP=$(curl -sS ipv4.icanhazip.com)
Name=$(curl -sS https://raw.githubusercontent.com/kenDevXD/ip/main/vps | grep $MYIP | awk '{print $2}')
echo $Name > /usr/local/etc/.$Name.ini
CekOne=$(cat /usr/local/etc/.$Name.ini)

Bloman () {
if [ -f "/etc/.$Name.ini" ]; then
CekTwo=$(cat /etc/.$Name.ini)
    if [ "$CekOne" = "$CekTwo" ]; then
        res="Expired"
    fi
else
res="Permission Accepted..."
fi
}

PERMISSION () {
    MYIP=$(curl -sS ipv4.icanhazip.com)
    IZIN=$(curl -sS https://raw.githubusercontent.com/kenDevXD/ip/main/vps | awk '{print $4}' | grep $MYIP)
    if [ "$MYIP" = "$IZIN" ]; then
    Bloman
    else
    res="Permission Denied!"
    fi
    BURIQ
}
red='\e[1;31m'
green='\e[1;32m'
NC='\e[0m'
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }
PERMISSION
if [ -f /home/needupdate ]; then
red "Your script need to update first !"
exit 0
elif [ "$res" = "Permission Accepted..." ]; then
echo -ne
else
red "Permission Denied!"
exit 0
fi
clear
BIBlack='\033[1;90m'      # Black
BIRed='\033[1;91m'        # Red
BIGreen='\033[1;92m'      # Green
BIYellow='\033[1;93m'     # Yellow
BIBlue='\033[1;94m'       # Blue
BIPurple='\033[1;95m'     # Purple
BICyan='\033[1;96m'       # Cyan
BIWhite='\033[1;97m'      # White
UWhite='\033[4;37m'       # White
On_IPurple='\033[0;105m'  #
On_IRed='\033[0;101m'
IBlack='\033[0;90m'       # Black
IRed='\033[0;91m'         # Red
IGreen='\033[0;92m'       # Green
IYellow='\033[0;93m'      # Yellow
IBlue='\033[0;94m'        # Blue
IPurple='\033[0;95m'      # Purple
ICyan='\033[0;96m'        # Cyan
IWhite='\033[0;97m'       # White
NC='\e[0m'
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }
# // Exporting Language to UTF-8

export LANG='en_US.UTF-8'
export LANGUAGE='en_US.UTF-8'


# // Export Color & Information
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[0;33m'
export BLUE='\033[0;34m'
export PURPLE='\033[0;35m'
export CYAN='\033[0;36m'
export LIGHT='\033[0;37m'
export NC='\033[0m'

MYIP=$(wget -qO- ipinfo.io/ip);
echo "Checking VPS"
function add-vls(){
clear
ISP=$(cat /etc/lokasi/isp)
CITY=$(cat /etc/lokasi/city)
TIMES="10"
CHATID=$(cat /etc/per/id)
KEY=$(cat /etc/per/token)
URL="https://api.telegram.org/bot$KEY/sendMessage"
cekray=`cat /root/log-install.txt | grep -ow "XRAY" | sort | uniq`
if [ "$cekray" = "XRAY" ]; then
domain=`cat /etc/xray/domain`
else
domain=`cat /etc/v2ray/domain`
fi
tls="$(cat ~/log-install.txt | grep -w "Vless WS TLS" | cut -d: -f2|sed 's/ //g')"
none="$(cat ~/log-install.txt | grep -w "Vless WS none TLS" | cut -d: -f2|sed 's/ //g')"
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1 ${NC} ${COLBG1}            ${WH}• Add Vless Account •              ${NC} $COLOR1 $NC"
echo -e "$COLOR1 ${NC} ${COLBG1}            ${WH}• Manual Uuid User •              ${NC} $COLOR1 $NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"

		read -rp "Username: " -e user
		CLIENT_EXISTS=$(grep -w $user /etc/xray/config.json | wc -l)

		if [[ ${CLIENT_EXISTS} == '1' ]]; then
clear
		echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
		echo -e "$COLOR1 ${NC} ${COLBG1}           ${WH}• Add Vless Account •              ${NC} $COLOR1 $NC"
		echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
			echo ""
			echo "A client with the specified name was already created, please choose another name."
			echo ""
			read -n 1 -s -r -p "Press any key to back on menu"
			menu-vless
		fi
	done
echo -e ""
read -p "Masukan (uuid): " uuid
echo -e ""
read -p "Expired (days): " masaaktif
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
harini=`date -d "0 days" +"%Y-%m-%d"`
sed -i '/#vless$/a\#vl '"$user $exp $uuid"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /etc/xray/config.json
sed -i '/#vlessgrpc$/a\#vlg '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /etc/xray/config.json
vlesslink1="vless://${uuid}@${domain}:$tls?path=/vless&security=tls&encryption=none&host=${domain}&type=ws&sni=bug.mu#${user}"
vlesslink2="vless://${uuid}@${domain}:80?path=/vless&security=none&encryption=none&host=${domain}&type=ws#${user}"
vlesslink3="vless://${uuid}@${domain}:$tls?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni=${domain}#${user}"

vless1="$(echo $vlesslink1 | base64 -w 0)"
vless2="$(echo $vlesslink2 | base64 -w 0)"
vless3="$(echo $vlesslink3 | base64 -w 0)"

TEXT="
<code>──────────────────────</code>
<code>    Xray/Vless Account</code>
<code>──────────────────────</code>
<code>Remarks      : </code> <code>${user}</code>
<code>Domain       : </code> <code>${domain}</code>
<code>City         : </code> <code>${CITY}</code>
<code>ISP          : </code> <code>${ISP}</code>
<code>Port TLS     : 443</code>
<code>Port NTLS    : 80, 8080</code>
<code>Port GRPC    : 443</code>
<code>User ID      : </code> <code>${uuid}</code>
<code>AlterId      : 0</code>
<code>Security     : auto</code>
<code>Network      : WS or gRPC</code>
<code>Path vless   : </code> <code>/vless</code>
<code>ServiceName  : </code> <code>/vless-grpc</code>
<code>──────────────────────</code>
<code>Link TLS     :</code> 
<code>${vless1}</code>
<code>──────────────────────</code>
<code>Link NTLS    :</code> 
<code>${vless2}</code>
<code>──────────────────────</code>
<code>Link GRPC    :</code> 
<code>${vless3}</code>
<code>──────────────────────</code>
<code>Created      : $harini</code>
<code>Expired On   : $exp</code>
<code>──────────────────────</code>
"

curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null

clear
clear
clear
clear
systemctl restart xray > /dev/null 2>&1
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC}    ${COLBG1}    ${WH}• XRAY VLESS PREMIUM •               ${NC} $COLOR1 $NC" | tee -a /etc/log-create-user.log
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} "
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Remarks      ${COLOR1}: ${WH}${user}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}ISP          ${COLOR1}: ${WH}$ISP" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}City         ${COLOR1}: ${WH}$CITY" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Domain       ${COLOR1}: ${WH}${domain}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Port TLS     ${COLOR1}: ${WH}443" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Port none TLS${COLOR1}: ${WH}80,8080" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}id           ${COLOR1}: ${WH}${uuid}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Encryption   ${COLOR1}: ${WH}none" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Network      ${COLOR1}: ${WH}ws" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Path         ${COLOR1}: ${WH}/vless" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Path         ${COLOR1}: ${WH}vless-grpc" | tee -a /etc/log-create-user.log
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} "
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${COLOR1}Link Websocket TLS      ${WH}:${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1${NC}${WH}${vlesslink1}${NC}"  | tee -a /etc/log-create-user.log
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${COLOR1}Link Websocket non TLS  ${WH}:${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1${NC}${WH}${vlesslink2}${NC}"  | tee -a /etc/log-create-user.log
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${COLOR1}Link gRPC               ${WH}:${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1${NC}${WH}${vlesslink3}${NC}"  | tee -a /etc/log-create-user.log
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Created      ${COLOR1}: ${WH}$harini" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Expired On   ${COLOR1}: ${WH}$exp" | tee -a /etc/log-create-user.log
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC}            ${WH}• TARAP kenDevXD TUNNELING •${NC}                 $COLOR1 $NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" | tee -a /etc/log-create-user.log
read -n 1 -s -r -p "Press any key to back on menu"
menu-uuid
}
clear
function add-xray(){
clear
ISP=$(cat /etc/lokasi/isp)
CITY=$(cat /etc/lokasi/city)
TIMES="10"
CHATID=$(cat /etc/per/id)
KEY=$(cat /etc/per/token)
URL="https://api.telegram.org/bot$KEY/sendMessage"
cekray=`cat /root/log-install.txt | grep -ow "XRAY" | sort | uniq`
if [ "$cekray" = "XRAY" ]; then
domain=`cat /etc/xray/domain`
else
domain=`cat /etc/v2ray/domain`
fi
tls="$(cat ~/log-install.txt | grep -w "Vmess WS TLS" | cut -d: -f2|sed 's/ //g')"
none="$(cat ~/log-install.txt | grep -w "Vmess WS none TLS" | cut -d: -f2|sed 's/ //g')"
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1 ${NC} ${COLBG1}            ${WH}• Add Vmess Account •              ${NC} $COLOR1 $NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"

		read -rp "Username: " -e user
		CLIENT_EXISTS=$(grep -w $user /etc/xray/config.json | wc -l)

		if [[ ${CLIENT_EXISTS} == '1' ]]; then
clear
            echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
            echo -e "$COLOR1 ${NC} ${COLBG1}            ${WH}• Add Vmess Account •              ${NC} $COLOR1 $NC"
            echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
            echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
            echo ""
            echo -e " A client with the specified name was already created, please choose another name."
            echo ""
            echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
            read -n 1 -s -r -p "Press any key to back on menu"
menu-vmess
		fi
	done
echo -e ""
read -p "Masukan (uuid): " uuid
echo -e ""
read -p "Expired (days): " masaaktif
harini=`date -d "0 days" +"%Y-%m-%d"`
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
sed -i '/#vmess$/a\#vm '"$user $exp"'\
},{"id": "'""$uuid""'","alterId": '"0"',"email": "'""$user""'"' /etc/xray/config.json
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
sed -i '/#vmessgrpc$/a\#vmg '"$user $exp $uuid"'\
},{"id": "'""$uuid""'","alterId": '"0"',"email": "'""$user""'"' /etc/xray/config.json
asu=`cat<<EOF
      {
      "v": "2",
      "ps": "${user}",
      "add": "${domain}",
      "port": "443",
      "id": "${uuid}",
      "aid": "0",
      "net": "ws",
      "path": "/vmess",
      "type": "none",
      "host": "${domain}",
      "tls": "tls"
}
EOF`
ask=`cat<<EOF
      {
      "v": "2",
      "ps": "${user}",
      "add": "${domain}",
      "port": "80",
      "id": "${uuid}",
      "aid": "0",
      "net": "ws",
      "path": "/vmess",
      "type": "none",
      "host": "${domain}",
      "tls": "none"
}
EOF`
grpc=`cat<<EOF
      {
      "v": "2",
      "ps": "${user}",
      "add": "${domain}",
      "port": "443",
      "id": "${uuid}",
      "aid": "0",
      "net": "grpc",
      "path": "vmess-grpc",
      "type": "none",
      "host": "${domain}",
      "tls": "tls"
}
EOF`
vmess_base641=$( base64 -w 0 <<< $vmess_json1)
vmess_base642=$( base64 -w 0 <<< $vmess_json2)
vmess_base643=$( base64 -w 0 <<< $vmess_json3)
vmesslink1="vmess://$(echo $asu | base64 -w 0)"
vmesslink2="vmess://$(echo $ask | base64 -w 0)"
vmesslink3="vmess://$(echo $grpc | base64 -w 0)"

TEXT="
<code>──────────────────────</code>
<code>  XRAY/VMSSS CREATED ACCOUNT UUID  </code>
<code>──────────────────────</code>
<code>Remarks      : </code> <code>${user}</code>
<code>Domain       : </code> <code>${domain}</code>
<code>ISP          : </code> <code>${ISP}</code>
<code>CITY         : </code> <code>${CITY}</code>
<code>Port TLS     : </code> <code>443</code>
<code>Port NTLS    : </code> <code>80, 8080</code>
<code>Port GRPC    : </code> <code>443</code>
<code>User ID      : </code> <code>${uuid}</code>
<code>AlterId      : 0</code>
<code>Security     : auto</code>
<code>Network      : WS or gRPC</code>
<code>Path         : </code> <code>/vmess</code>
<code>ServiceName  : </code> <code>vmess-grpc</code>
<code>──────────────────────</code>
<code>Link TLS     :</code> 
<code>${vmesslink1}</code>
<code>──────────────────────</code>
<code>Link NTLS    :</code> 
<code>${vmesslink2}</code>
<code>──────────────────────</code>
<code>Link GRPC    :</code> 
<code>${vmesslink3}</code>
<code>──────────────────────</code>
<code>Created      : $harini</code>
<code>──────────────────────</code>
<code>Expired On   : $exp</code>
<code>──────────────────────</code>
"

curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null

clear
clear
clear
clear
systemctl restart xray > /dev/null 2>&1
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC}   ${COLBG1}${WH}      • XRAY VMESS PREMIUM •              ${NC} $COLOR1 $NC" | tee -a /etc/log-create-user.log
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Remarks       ${COLOR1}: ${WH}${user}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}ISP           ${COLOR1}: ${WH}$ISP" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}City          ${COLOR1}: ${WH}$CITY" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Domain        ${COLOR1}: ${WH}${domain}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Port TLS      ${COLOR1}: ${WH}443" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Port none TLS ${COLOR1}: ${WH}80,8080" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Port gRPC     ${COLOR1}: ${WH}443" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}id            ${COLOR1}: ${WH}${uuid}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}alterId       ${COLOR1}: ${WH}0" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Security      ${COLOR1}: ${WH}auto" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Network       ${COLOR1}: ${WH}ws" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Path          ${COLOR1}: ${WH}/vmess" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}ServiceName   ${COLOR1}: ${WH}vmess-grpc" | tee -a /etc/log-create-user.log
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${COLOR1}Link Websocket TLS      ${WH}:${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1${NC}${WH}${vmesslink1}${NC}"  | tee -a /etc/log-create-user.log
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${COLOR1}Link Websocket None TLS ${WH}: ${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1${NC}${WH}${vmesslink2}${NC}"  | tee -a /etc/log-create-user.log
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${COLOR1}Link Websocket GRPC     ${WH}: ${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1${NC}${WH}${vmesslink3}${NC}"  | tee -a /etc/log-create-user.log
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Created        ${COLOR1}: ${WH}$harini" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Expired On     ${COLOR1}: ${WH}$exp" | tee -a /etc/log-create-user.log
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC}           ${WH}• TARAP kenDevXD TUNNELING •${NC}                 $COLOR1 $NC" | tee -a /etc/log-create-user.log
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" | tee -a /etc/log-create-user.log
echo "" | tee -a /etc/log-create-user.log
read -n 1 -s -r -p "Press any key to back on menu uuid"
menu-uuid
}
function add-trj(){
clear
ISP=$(cat /etc/lokasi/isp)
CITY=$(cat /etc/lokasi/city)
TIMES="10"
CHATID=$(cat /etc/per/id)
KEY=$(cat /etc/per/token)
URL="https://api.telegram.org/bot$KEY/sendMessage"
cekray=`cat /root/log-install.txt | grep -ow "XRAY" | sort | uniq`
if [ "$cekray" = "XRAY" ]; then
domain=`cat /etc/xray/domain`
else
domain=`cat /etc/v2ray/domain`
fi
tls="$(cat ~/log-install.txt | grep -w "Trojan WS TLS" | cut -d: -f2|sed 's/ //g')"
ntls="$(cat ~/log-install.txt | grep -w "Trojan WS none TLS" | cut -d: -f2|sed 's/ //g')"
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${user_EXISTS} == '0' ]]; do
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1 ${NC} ${COLBG1}            ${WH}• Add Trojan Account •             ${NC} $COLOR1 $NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"

		read -rp "Username: " -e user
		user_EXISTS=$(grep -w $user /etc/xray/config.json | wc -l)

		if [[ ${user_EXISTS} == '1' ]]; then
clear
		echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
                echo -e "$COLOR1 ${NC} ${COLBG1}            ${WH}• Add Trojan Account •             ${NC} $COLOR1 $NC"
                echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
			echo ""
			echo "A client with the specified name was already created, please choose another name."
			echo ""
                        echo -e "$COLOR1━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
			read -n 1 -s -r -p "Press any key to back on menu"
			menu-trojan
		fi
	done
echo -e ""
read -p "masukan (uuid): " uuid
echo -e ""
read -p "Expired (days): " masaaktif
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
harini=`date -d "0 days" +"%Y-%m-%d"`
sed -i '/#trojanws$/a\#tr '"$user $exp $uuid"'\
},{"password": "'""$uuid""'","email": "'""$user""'"' /etc/xray/config.json
sed -i '/#trojangrpc$/a\#trg '"$user $exp"'\
},{"password": "'""$uuid""'","email": "'""$user""'"' /etc/xray/config.json

trojanlink1="trojan://${uuid}@${domain}:443?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni=${domain}#${user}"
trojanlink="trojan://${uuid}@${domain}:443?path=%2Ftrojan-ws&security=tls&host=$sni&type=ws&sni=${domain}#${user}"

trojan1="$(echo $trojanlink1 | base64 -w 0)"
trojan2="$(echo $trojanlink | base64 -w 0)"

TEXT="
<code>──────────────────────</code>
<code>    Xray TROJAN Account</code>
<code>──────────────────────</code>
<code>Remarks      : </code> <code>${user}</code>
<code>Domain       : </code> <code>${domain}</code>
<code>City         : </code> <code>${CITY}</code>
<code>ISP          : </code> <code>${ISP}</code>
<code>Port TLS     : </code> <code>443</code>
<code>Port none TLS: </code> <code>80,8080</code>
<code>Port GRPC    : </code> <code>443</code>
<code>User ID      : </code> <code>${uuid}</code>
<code>AlterId      : 0</code>
<code>Security     : auto</code>
<code>Network      : WS or gRPC</code>
<code>Path WS      : </code> <code>/trojan-ws</code>
<code>Path GRPC    : </code> <code>/trojan-grpc</code>
<code>──────────────────────</code>
<code>Link TLS     :</code> 
<code>${trojan2}</code>
<code>──────────────────────</code>
<code>Link GRPC    :</code> 
<code>${trojan1}</code>
<code>──────────────────────</code>
<code>Created      : $harini</code>
<code>──────────────────────</code>
<code>Expired On   : $exp</code>
<code>──────────────────────</code>
"

curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null

clear
clear
clear
clear
systemctl restart xray > /dev/null 2>&1
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC}    ${COLBG1} ${WH}• XRAY TROJAN PREMIUM •              ${NC} $COLOR1 $NC" | tee -a /etc/log-create-user.log
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} "
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Remarks      ${COLOR1}: ${WH}${user}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}ISP          ${COLOR1}: ${WH}$ISP" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}City         ${COLOR1}: ${WH}$CITY" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Host/IP      ${COLOR1}: ${WH}${domain}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Port TLS     ${COLOR1}: ${WH}443" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Port none TLS${COLOR1}: ${WH}80,8080" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Port gRPC    ${COLOR1}: ${WH}443" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Key          ${COLOR1}: ${WH}${uuid}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Path WS      ${COLOR1}: ${WH}/trojan-ws" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}ServiceName  ${COLOR1}: ${WH}trojan-grpc" | tee -a /etc/log-create-user.log
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} "
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Link TLS     ${COLOR1}: ${WH}${trojanlink}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} "
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Link gRPC    ${COLOR1}: ${WH}${trojanlink1}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} "
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Created      ${COLOR1}: ${WH}$harini" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} ${WH}Expired On   ${COLOR1}: ${WH}$exp" | tee -a /etc/log-create-user.log
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" | tee -a /etc/log-create-user.log
echo -e "$COLOR1 ${NC} "
echo -e "$COLOR1┌────────────────────── ${WH}BY${NC} ${COLOR1}───────────────────────┐${NC}"
echo -e "$COLOR1 ${NC}            ${WH}• TARAP kenDevXD TUNNELING •              $COLOR1 $NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" | tee -a /etc/log-create-user.log
echo "" | tee -a /etc/log-create-user.log
read -n 1 -s -r -p "Press any key to back on menu"
menu-uuid
}
clear
echo -e "${BICyan} ┌─────────────────────────────────────────────────────┐${NC}"
echo -e "       ${BIWhite}${UWhite}CREATE ACCOUNT UUID MANUAL ${NC}"
echo -e ""
echo -e "     ${BICyan}[${BIWhite}01${BICyan}] UUID ACCOUNT VMESS MANUAL    "
echo -e "     ${BICyan}[${BIWhite}02${BICyan}] UUID ACCOUNT VLESS MANUAL     "
echo -e "     ${BICyan}[${BIWhite}03${BICyan}] UUID ACCOUNT TROJAN MANUAL    "
echo -e " ${BICyan}└─────────────────────────────────────────────────────┘${NC}"
echo -e "     ${BIYellow}Press x or [ Ctrl+C ] • To-${BIWhite}Exit${NC}"
echo ""
read -p " Select menu : " opt
echo -e ""
case $opt in
1) clear ; add-xray ;;
2) clear ; add-vls ;;
3) clear ; add-trj ;;
0) clear ; menu ;;
x) clear ; menu ;;
*) echo "anda salah tekan cok" ; sleep 1 ; menu-uuid ;;
esac
