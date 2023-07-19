#!/bin/bash
# //====================================================
# //	System Request:Debian 9+/Ubuntu 18.04+/20+
# //	Author:	kenDevXD
# //	Dscription: Xray Menu Management
# //	email: merahjambo@gmail.com
# //  telegram: https://t.me/Baung2012
# //====================================================
# // font color configuration | TARAP KUHING AUTOSCRIPT
red() { echo -e "\\033[32;1m${*}\\033[0m"; }
TIMES="10"
CHATID=`cat /etc/per/id`
KEY=`cat /etc/per/token`
URL="https://api.telegram.org/bot$KEY/sendMessage"
domain=$(cat /etc/xray/domain)
PUB=$(cat /etc/slowdns/server.pub)
CITY=$(cat /etc/lokasi/city)
ISP=$(cat /etc/lokasi/isp)
NS=$(cat /etc/xray/dns)
clear
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
  clear
  echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  echo -e "\e[42m         Add Xray/Vmess Account          \E[0m"
  echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"

  read -rp "User: " -e user
  CLIENT_EXISTS=$(grep -w $user /etc/xray/config.json | wc -l)

  if [[ ${CLIENT_EXISTS} == '1' ]]; then
    clear
    echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\e[42m         Add Xray/Vmess Account          \E[0m"
    echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
    echo "A client with the specified name was already created, please choose another name."
    echo ""
    echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
  fi
done

uuid=$(cat /proc/sys/kernel/random/uuid)
read -p "Expired (days)  : " masaaktif
echo -e ""
read -p "Limit Ip (Login): " Ip
exp=$(date -d "$masaaktif days" +"%Y-%m-%d")
sed -i '/#vmess$/a\#vm '"$user $exp"'\
},{"id": "'""$uuid""'","alterId": '"0"',"email": "'""$user""'"' /etc/xray/config.json
exp=$(date -d "$masaaktif days" +"%Y-%m-%d")
sed -i '/#vmessgrpc$/a\#vmg '"$user $exp"'\
},{"id": "'""$uuid""'","alterId": '"0"',"email": "'""$user""'"' /etc/xray/config.json
VMESS_WS=`cat<<EOF
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
VMESS_NON_TLS=`cat<<EOF
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
VMESS_GRPC=`cat<<EOF
      {
      "v": "2",
      "ps": "${user}",
      "add": "${domain}",
      "port": "443",
      "id": "${uuid}",
      "aid": "0",
      "net": "grpc",
      "path": "/vmess-grpc",
      "type": "none",
      "host": "${domain}",
      "tls": "tls"
}
EOF`
VMESS_OPOK=`cat<<EOF  
      { 
      "v": "2", 
      "ps": "${user}",  
      "add": "${domain}", 
      "port": "80", 
      "id": "${uuid}",  
      "aid": "0", 
      "net": "ws",
      "path": "http://tsel.me/worryfree",
      "type": "none", 
      "host": "tsel.me",  
      "tls": "none" 
} 
EOF`
cat >/etc/kenDevXD/public_html/vmess-$user.txt <<-END
====================================================================
             P R O J E C T  O F  T A R A P  K U H I N G
                       [Freedom Internet]
====================================================================
        https://github.com/kenDevXD/vps
====================================================================
              Format Vmess WS (CDN)
====================================================================

- name: kenDevXD-Vmess-$user-WS (CDN)
  type: vmess
  server: ${domain}
  port: 443
  uuid: ${uuid}
  alterId: 0
  cipher: auto
  udp: true
  tls: true
  skip-cert-verify: true
  servername: ${domain}
  network: ws
  ws-opts:
    path: /vmess
    headers:
      Host: ${domain}
_______________________________________________________
              Format Vmess WS (CDN) Non TLS
_______________________________________________________

- name: kenDevXD-$user-WS (CDN) Non TLS
  type: vmess
  server: ${domain}
  port: 80
  uuid: ${uuid}
  alterId: 0
  cipher: auto
  udp: true
  tls: false
  skip-cert-verify: false
  servername: ${domain}
  network: ws
  ws-opts:
    path: /vmess
    headers:
      Host: ${domain}
_______________________________________________________
              Format Vmess gRPC (SNI)
_______________________________________________________

- name: kenDevXD-$user-gRPC (SNI)
  server: ${domain}
  port: 443
  type: vmess
  uuid: ${uuid}
  alterId: 0
  cipher: auto
  network: grpc
  tls: true
  servername: ${domain}
  skip-cert-verify: true
  grpc-opts:
  grpc-service-name: vmess-grpc

_______________________________________________________
        Format Vmess WS (CDN) Non TLS Opok
_______________________________________________________

- name: kenDevXD-$user-WS (CDN) Non TLS
  type: vmess
  server: ${domain}
  port: 80
  uuid: ${uuid}
  alterId: 0
  cipher: auto
  udp: true
  tls: false
  skip-cert-verify: true
  servername: comunity.instagram.com
  network: ws
  ws-opts:
    path: http://tsel.me/worryfree
    headers:
      Host: ${domain}
_______________________________________________________
              Link Vmess Account
_______________________________________________________
Link TLS : vmess://$(echo $VMESS_WS | base64 -w 0)
_______________________________________________________
Link none TLS : vmess://$(echo $VMESS_NON_TLS | base64 -w 0)
_______________________________________________________
Link GRPC : vmess://$(echo $VMESS_GRPC | base64 -w 0)
_______________________________________________________
Link Opok : vmess://$(echo $VMESS_OPOK | base64 -w 0)
_______________________________________________________



END
vmesslink1="vmess://$(echo $VMESS_WS | base64 -w 0)"
vmesslink2="vmess://$(echo $VMESS_NON_TLS | base64 -w 0)"
vmesslink3="vmess://$(echo $VMESS_GRPC | base64 -w 0)"
vmesslink4="vmess://$(echo $VMESS_OPOK | base64 -w 0)"
TEXT="
<code>───────────────────────────</code>
<code>    Xray/Vmess Account</code>
<code>───────────────────────────</code>
<code>Remarks      : ${user}</code>
<code>Domain       : ${domain}</code>
<code>Host Slowdns : ${NS}</code>
<code>Pub Key      : ${PUB}</code>
<code>Location     : $CITY</code>
<code>User Quota   : ${Quota} GB</code>
<code>Port TLS     : 443</code>
<code>Port DNS     : 443, 53</code>
<code>Port NTLS    : 80, 8080, 2086</code>
<code>Port GRPC    : 443</code>
<code>User ID      : ${uuid}</code>
<code>AlterId      : 0</code>
<code>Security     : auto</code>
<code>Network      : WS or gRPC</code>
<code>Path TLS     : (/vmess) (/custom)</code>
<code>Path NLS     : (/vmess) (/custom)</code>
<code>Path Dynamic : CF-XRAY:http://bug.com</code>
<code>ServiceName  : vmess-grpc</code>
<code>───────────────────────────</code>
<code>Link TLS     :</code> 
<code>${vmesslink1}</code>
<code>───────────────────────────</code>
<code>Link NTLS    :</code> 
<code>${vmesslink2}</code>
<code>───────────────────────────</code>
<code>Link GRPC    :</code> 
<code>${vmesslink3}</code>
<code>───────────────────────────</code>
<code>Link Opok    :</code> 
<code>${vmesslink4}</code>
<code>───────────────────────────</code>
<code>Format OpenClash :</code> http://${domain}:81/vmess-$user.txt
<code>───────────────────────────</code>
<code>Expired On : $exp</code>
"
systemctl restart xray
systemctl reload nginx
service cron restart

if [ ! -e /etc/vmess ]; then
  mkdir -p /etc/vmess
fi

if [ -z ${Ip} ]; then
  Ip="0"
fi

c=$(echo "${Ip}" | sed 's/[^0-9]*//g')
d=$((${c} * 1000 * 1000 * 1000))

if [[ ${c} != "0" ]]; then
  echo "${d}" >/etc/vmess/${user}
fi
DATADB=$(cat /etc/vmess/.vmess.db | grep "^#vmg" | grep -w "${user}" | awk '{print $2}')
if [[ "${DATADB}" != '' ]]; then
  sed -i "/\b${user}\b/d" /etc/vmess/.vmess.db
fi
echo "#vmg ${user} ${exp} ${uuid}" >>/etc/vmess/.vmess.db
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
clear
echo -e "\033[1;93m───────────────────────────\033[0m" | tee -a /etc/kenDevXD/user.log
echo -e "\e[42m    Xray/Vmess Account     \E[0m" | tee -a /etc/kenDevXD/user.log
echo -e "\033[1;93m───────────────────────────\033[0m" | tee -a /etc/kenDevXD/user.log
echo -e "Remarks      : ${user}" | tee -a /etc/kenDevXD/user.log
echo -e "Domain       : ${domain}" | tee -a /etc/kenDevXD/user.log
echo -e "Host Slowdns : ${NS}" | tee -a /etc/kenDevXD/user.log
echo -e "Pub Key      : ${PUB}" | tee -a /etc/kenDevXD/user.log
echo -e "Location     : $CITY" | tee -a /etc/kenDevXD/user.log
echo -e "User Quota   : ${Quota} GB" | tee -a /etc/kenDevXD/user.log
echo -e "Port TLS     : 443" | tee -a /etc/kenDevXD/user.log
echo -e "Port NTLS    : 80, 8080, 2086" | tee -a /etc/kenDevXD/user.log
echo -e "Port DNS     : 443, 53 " | tee -a /etc/kenDevXD/user.log
echo -e "Port GRPC    : 443" | tee -a /etc/kenDevXD/user.log
echo -e "User ID      : ${uuid}" | tee -a /etc/kenDevXD/user.log
echo -e "AlterId      : 0" | tee -a /etc/kenDevXD/user.log
echo -e "Security     : auto" | tee -a /etc/kenDevXD/user.log
echo -e "Network      : WS or gRPC" | tee -a /etc/kenDevXD/user.log
echo -e "Path TLS     : (/multi path)/vmess " | tee -a /etc/kenDevXD/user.log
echo -e "Path NLS     : (/multi path)/vmess " | tee -a /etc/kenDevXD/user.log
echo -e "Path Dynamic : CF-XRAY:http://bug.com " | tee -a /etc/kenDevXD/user.log
echo -e "ServiceName  : vmess-grpc" | tee -a /etc/kenDevXD/user.log
echo -e "\033[1;93m───────────────────────────\033[0m" | tee -a /etc/kenDevXD/user.log
echo -e "Link TLS     : ${vmesslink1}" | tee -a /etc/kenDevXD/user.log
echo -e "\033[1;93m───────────────────────────\033[0m" | tee -a /etc/kenDevXD/user.log
echo -e "Link NTLS    : ${vmesslink2}" | tee -a /etc/kenDevXD/user.log
echo -e "\033[1;93m───────────────────────────\033[0m" | tee -a /etc/kenDevXD/user.log
echo -e "Link GRPC    : ${vmesslink3}" | tee -a /etc/kenDevXD/user.log
echo -e "\033[1;93m───────────────────────────\033[0m" | tee -a /etc/kenDevXD/user.log
echo -e "Link OPOK    : ${vmesslink4}" | tee -a /etc/kenDevXD/user.log
echo -e "\033[1;93m───────────────────────────\033[0m" | tee -a /etc/kenDevXD/user.log
echo -e "Format OpenClash : https://${domain}:81/vmess-$user.txt" | tee -a /etc/kenDevXD/user.log
echo -e "\033[1;93m───────────────────────────\033[0m" | tee -a /etc/kenDevXD/user.log
echo -e "Expired On : $exp" | tee -a /etc/kenDevXD/user.log
echo -e "" | tee -a /etc/kenDevXD/user.log
read -n 1 -s -r -p "Press any key to back on menu"

menu
