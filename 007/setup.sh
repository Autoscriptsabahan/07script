#!/bin/bash
# ******************************************
# Program: Apache07 Servis Apache07
# Website: Apache07.tk
# Developer: samrey steven
# Nickname: Apache07
# Date: 22-07-2016
# Last Updated: 22-10-2017
# ******************************************
# MULA SETUP
myip=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1`;
myint=`ifconfig | grep -B1 "inet addr:$myip" | head -n1 | awk '{print $1}'`;
if [ $USER != 'root' ]; then
echo "Sorry, for run the script please using root user"
exit 1
fi
if [[ "$EUID" -ne 0 ]]; then
echo "Sorry, you need to run this as root"
exit 2
fi
if [[ ! -e /dev/net/tun ]]; then
echo "TUN is not available"
exit 3
fi
echo "
AUTOSCRIPT BY OrangKuatSabahanTerkini
AMBIL PERHATIAN !!!"
clear
echo "MULA SETUP"
clear

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# go to root
cd
                                      
# set repo
wget -O /etc/apt/sources.list "https://raw.githubusercontent.com/Apache07/example7/master/989/sources.list.debian7"
wget https://raw.githubusercontent.com/Apache07/example7/master/989/script/dotdeb.gpg
wget https://raw.githubusercontent.com/Apache07/example7/master/989/jcameron-key.asc
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
cat jcameron-key.asc | apt-key add -;rm jcameron-key.asc

# update
apt-get update; apt-get -y upgrade;

# install webserver
apt-get -y install nginx php5-fpm php5-cli

# install essential package
apt-get -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs openvpn vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh mrtg snmp snmpd snmp-mibs-downloader unzip unrar rsyslog debsums rkhunter 
apt-get -y install build-essential 

# Disable Exim
service exim4 stop
sysv-rc-conf exim4 off

# update apt-file
apt-file update

# setting vnstat
vnstat -u -i $ether
service vnstat restart

# text gambar
apt-get install boxes

# color text
cd
rm -rf /root/.bashrc
wget -O /root/.bashrc "https://raw.githubusercontent.com/Apache07/example7/master/989/.bashrc"

# install lolcat
sudo apt-get -y install ruby
sudo gem install lolcat

# install webserver
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/Apache07/example7/master/989/nginx.conf"
mkdir -p /home/vps/public_html
echo "<pre>Setup by Chandra989</pre>" > /home/vps/public_html/index.html
echo "<?php phpinfo(); ?>" > /home/vps/public_html/info.php
wget -O /etc/nginx/conf.d/vps.conf "vpn989.com/script/vps.conf"
sed -i 's/listen = \/var\/run\/php5-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php5/fpm/pool.d/www.conf
service php5-fpm restart
service nginx restart


# install badvpn
wget -O /usr/bin/badvpn-udpgw "https://github.com/Apache07/example7/blob/master/989/badvpn-udpgw?raw=true" 
if [ "$OS" == "x86_64" ]; then 
  wget -O /usr/bin/badvpn-udpgw "https://github.com/Apache07/example7/blob/master/989/badvpn-udpgw64?raw=true" 
fi 
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local 
chmod +x /usr/bin/badvpn-udpgw 
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 

# Install Mrtg
wget -O /etc/snmp/snmpd.conf "https://raw.githubusercontent.com/Apache07/example7/master/989/snmpd.conf"
wget -O /root/mrtg-mem.sh "https://raw.githubusercontent.com/Apache07/example7/master/989/mrtg-mem.sh"
chmod +x /root/mrtg-mem.sh
cd /etc/snmp/
sed -i 's/TRAPDRUN=no/TRAPDRUN=yes/g' /etc/default/snmpd
service snmpd restart
snmpwalk -v 1 -c public localhost 1.3.6.1.4.1.2021.10.1.3.1
mkdir -p /home/vps/public_html/mrtg
cfgmaker --zero-speed 100000000 --global 'WorkDir: /home/vps/public_html/mrtg' --output /etc/mrtg.cfg public@localhost
curl "https://raw.githubusercontent.com/Apache07/example7/master/989/mrtg.conf" >> /etc/mrtg.cfg
sed -i 's/WorkDir: \/var\/www\/mrtg/# WorkDir: \/var\/www\/mrtg/g' /etc/mrtg.cfg
sed -i 's/# Options\[_\]: growright, bits/Options\[_\]: growright/g' /etc/mrtg.cfg
indexmaker --output=/home/vps/public_html/mrtg/index.html /etc/mrtg.cfg
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
cd

# setting port ssh
sed -i '/Port 22/Port  143' /etc/ssh/sshd_config
#sed -i '/Port 22/a Port  80' /etc/ssh/sshd_config
sed -i 's/Port 22/Port  22/g' /etc/ssh/sshd_config
sed -i 's/#Banner/Banner/g' /etc/ssh/sshd_config
service ssh restart

# install dropbear
apt-get -y install dropbear 
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear 
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=443/g' /etc/default/dropbear 
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 443 -p 80"/g' /etc/default/dropbear 
echo "/bin/false" >> /etc/shells 
echo "/usr/sbin/nologin" >> /etc/shells 
service ssh restart 
service dropbear restart 

# install vnstat gui
cd /home/vps/public_html/
wget https://github.com/Apache07/example7/blob/master/989/vnstat_php_frontend-1.5.1.tar.gz?raw=true
tar xvfz vnstat_php_frontend-1.5.1.tar.gz
rm vnstat_php_frontend-1.5.1.tar.gz
mv vnstat_php_frontend-1.5.1 vnstat
cd vnstat
sed -i "s/eth0/$ether/g" config.php
sed -i "s/\$iface_list = array('venet0', 'sixxs');/\$iface_list = array($ether);/g" config.php
sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
sed -i 's/Internal/Internet/g' config.php
sed -i '/SixXS IPv6/d' config.php
cd

#if [[ $ether = "eth0" ]]; then
#	wget -O /etc/iptables.conf "https://raw.githubusercontent.com/Apache07/example7/master/989/iptables.up.rules.eth0
#else
#	wget -O /etc/iptables.conf "https://raw.githubusercontent.com/Apache07/example7/master/989/iptables.up.rules.venet0"
#fi

#sed -i $MYIP2 /etc/iptables.conf;
#iptables-restore < /etc/iptables.conf;

# install fail2ban
apt-get update;apt-get -y install fail2ban;service fail2ban restart

# install squid3
wget https://raw.githubusercontent.com/Apache07/example7/master/989/squid.sh && chmod 100 squid.sh && ./squid.sh

# install webmin
cd
#wget -O webmin-current.deb http://prdownloads.sourceforge.net/webadmin/webmin_1.760_all.deb
wget -O webmin-current.deb "https://github.com/Apache07/example7/blob/master/989/webmin-current.deb?raw=true"
dpkg -i --force-all webmin-current.deb
apt-get -y -f install;
#sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
rm -f /root/webmin-current.deb
apt-get -y --force-yes -f install libxml-parser-perl
service webmin restart
service vnstat restart

# install pptp vpn
wget -O /root/pptp.sh "https://raw.githubusercontent.com/Apache07/example7/master/989/pptp.sh"
chmod +x pptp.sh
./pptp.sh

# Instal DDOS Flate
if [ -d '/usr/local/ddos' ]; then
	echo; echo; echo "Please un-install the previous version first"
	exit 0
else
	mkdir /usr/local/ddos
fi
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'
echo 'Please send in your comments and/or suggestions to zaf@vsnl.com'

# download script
cd
wget -O /usr/bin/benchmark "https://raw.githubusercontent.com/Apache07/example7/master/989/benchmark.sh"
wget -O /usr/bin/speedtest  "https://raw.githubusercontent.com/Apache07/example7/master/989/speedtest_cli.py"
wget -O /usr/bin/ps-mem "https://raw.githubusercontent.com/Apache07/example7/master/989/ps_mem.py"
wget -O /usr/bin/dropmon "https://raw.githubusercontent.com/Apache07/example7/master/989/dropmon.sh"
wget -O /usr/bin/menu "https://raw.githubusercontent.com/Apache07/example7/master/989/menu"
wget -O /usr/bin/user-active-list "https://raw.githubusercontent.com/Apache07/example7/master/989/user-active-list.sh"
wget -O /usr/bin/user-add "https://raw.githubusercontent.com/Apache07/example7/master/989/user-add.sh"
wget -O /usr/bin/user-add-pptp "https://raw.githubusercontent.com/Apache07/example7/master/989/user-add-pptp.sh"
wget -O /usr/bin/user-del "https://raw.githubusercontent.com/Apache07/example7/master/989/user-del.sh"
wget -O /usr/bin/disable-user-expire "https://raw.githubusercontent.com/Apache07/example7/master/989/disable-user-expire.sh"
wget -O /usr/bin/delete-user-expire "https://raw.githubusercontent.com/Apache07/example7/master/989/delete-user-expire.sh"
wget -O /usr/bin/banned-user "https://raw.githubusercontent.com/Apache07/example7/master/989/banned-user.sh"
wget -O /usr/bin/unbanned-user "https://raw.githubusercontent.com/Apache07/example7/master/989/unbanned-user.sh"
wget -O /usr/bin/user-expire-list "https://raw.githubusercontent.com/Apache07/example7/master/989/user-expire-list.sh"
wget -O /usr/bin/user-gen "https://raw.githubusercontent.com/Apache07/example7/master/989/user-gen.sh"
wget -O /usr/bin/userlimit.sh "https://raw.githubusercontent.com/Apache07/example7/master/989/userlimit.sh"
wget -O /usr/bin/userlimitssh.sh "https://raw.githubusercontent.com/Apache07/example7/master/989/userlimitssh.sh"
wget -O /usr/bin/user-list "https://raw.githubusercontent.com/Apache07/example7/master/989/user-list.sh"
wget -O /usr/bin/user-login "https://raw.githubusercontent.com/Apache07/example7/master/989/user-login.sh"
wget -O /usr/bin/user-pass "https://raw.githubusercontent.com/Apache07/example7/master/989/user-pass.sh"
wget -O /usr/bin/user-renew "https://raw.githubusercontent.com/Apache07/example7/master/989/user-renew.sh"
wget -O /usr/bin/clearcache.sh "https://raw.githubusercontent.com/Apache07/example7/master/989/clearcache.sh"
wget -O /usr/bin/bannermenu "https://raw.githubusercontent.com/Apache07/example7/master/989/bannermenu"
cd

#rm -rf /etc/cron.weekly/
#rm -rf /etc/cron.hourly/
#rm -rf /etc/cron.monthly/
rm -rf /etc/cron.daily/
wget -O /root/passwd "https://raw.githubusercontent.com/Apache07/example7/master/989/passwd.sh"
chmod +x /root/passwd
echo "01 23 * * * root /root/passwd" > /etc/cron.d/passwd

echo "*/30 * * * * root service dropbear restart" > /etc/cron.d/dropbear
echo "00 23 * * * root /usr/bin/disable-user-expire" > /etc/cron.d/disable-user-expire
echo "0 */12 * * * root /sbin/reboot" > /etc/cron.d/reboot
#echo "00 01 * * * root echo 3 > /proc/sys/vm/drop_caches && swapoff -a && swapon -a" > /etc/cron.d/clearcacheram3swap
echo "*/30 * * * * root /usr/bin/clearcache.sh" > /etc/cron.d/clearcache1

cd
chmod +x /usr/bin/benchmark
chmod +x /usr/bin/speedtest
chmod +x /usr/bin/ps-mem
#chmod +x /usr/bin/autokill
chmod +x /usr/bin/dropmon
chmod +x /usr/bin/menu
chmod +x /usr/bin/user-active-list
chmod +x /usr/bin/user-add
chmod +x /usr/bin/user-add-pptp
chmod +x /usr/bin/user-del
chmod +x /usr/bin/disable-user-expire
chmod +x /usr/bin/delete-user-expire
chmod +x /usr/bin/banned-user
chmod +x /usr/bin/unbanned-user
chmod +x /usr/bin/user-expire-list
chmod +x /usr/bin/user-gen
chmod +x /usr/bin/userlimit.sh
chmod +x /usr/bin/userlimitssh.sh
chmod +x /usr/bin/user-list
chmod +x /usr/bin/user-login
chmod +x /usr/bin/user-pass
chmod +x /usr/bin/user-renew
chmod +x /usr/bin/clearcache.sh
chmod +x /usr/bin/bannermenu
cd

# swap ram
dd if=/dev/zero of=/swapfile bs=1024 count=1024k

# buat swap
mkswap /swapfile

# jalan swapfile
swapon /swapfile

#auto star saat reboot
wget https://raw.githubusercontent.com/Apache07/example7/master/989/script/fstab
mv ./fstab /etc/fstab
chmod 644 /etc/fstab
sysctl vm.swappiness=10
#permission swapfile
chown root:root /swapfile 
chmod 0600 /swapfile
cd

# Blockir Torrent
iptables -A OUTPUT -p tcp --dport 6881:6889 -j DROP
iptables -A OUTPUT -p udp --dport 1024:65534 -j DROP
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP

# Restart Service
chown -R www-data:www-data /home/vps/public_html
service nginx start
service php-fpm start
service vnstat restart
service ssh restart
service squid3 restart
service webmin restart
service fail2ban restart

# info
clear
echo "                  System Created by Vpn989"
echo "          ==========***********==========="
echo "==========================================================="
echo "Service :" | tee -a log-install.txt
echo "---------" | tee -a log-install.txt
echo "OpenSSH  : 22, 143" | tee -a log-install.txt
echo "Dropbear : 443, 80" | tee -a log-install.txt
echo "Squid3   : 8080 limit to IP $MYIP" | tee -a log-install.txt
#echo "OpenVPN  : TCP 1194 (client config : http://$MYIP:989/client.ovpn)" | tee -a log-install.txt
echo "badvpn   : badvpn-udpgw port 7300" | tee -a log-install.txt
echo "PPTP VPN : TCP 1723" | tee -a log-install.txt
echo "nginx    : 989" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Tools :" | tee -a log-install.txt
echo "-------" | tee -a log-install.txt
echo "axel, bmon, htop, iftop, mtr, rkhunter, nethogs: nethogs $ether" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Script :" | tee -a log-install.txt
echo "--------" | tee -a log-install.txt
echo "MENU"
echo "" | tee -a log-install.txt
echo "Fitur lain :" | tee -a log-install.txt
echo "------------" | tee -a log-install.txt
echo "Webmin            : http://$MYIP:10000/" | tee -a log-install.txt
echo "vnstat            : http://$MYIP:989/vnstat/ [Cek Bandwith]" | tee -a log-install.txt
echo "Timezone : Asia/Malaysia"
echo "Fail2Ban : [on]"
echo "IPv6     : [off]"
echo "Ddos Protect : [on]"
echo "Torrent Protect [on]"
echo "Website  : http://vpn989.com"
echo ""
echo "                        Sila Reboot VPS Anda !"
echo "==========================================================="
rm debian.sh
