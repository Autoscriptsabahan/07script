#!/bin/bash

if [ $USER != 'root' ]; then
	echo "Maaf, Anda harus menjalankan ini sebagai root"
	exit
fi

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ipv4.icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";
ether=`ifconfig | cut -c 1-8 | sort | uniq -u | grep venet0 | grep -v venet0:`
if [ "$ether" = "" ]; then
        ether=eth0
fi

# go to root
cd

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# install wget and curl
apt-get update;apt-get -y install wget curl;

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart

# set repo
wget -O /etc/apt/sources.list "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/sources.list.debian7"
wget "http://www.dotdeb.org/dotdeb.gpg"
wget "http://www.webmin.com/jcameron-key.asc"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
cat jcameron-key.asc | apt-key add -;rm jcameron-key.asc

# remove unused
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;
#apt-get -y autoremove;

# update
apt-get update;apt-get -y upgrade;

# install webserver
apt-get -y install nginx php5-fpm php5-cli

# install essential package
echo "mrtg mrtg/conf_mods boolean true" | debconf-set-selections
apt-get -y install bmon 
apt-get -y install iftop 
apt-get -y install htop 
apt-get -y install nmap 
apt-get -y install axel 
apt-get -y install nano 
apt-get -y install iptables 
apt-get -y install traceroute 
apt-get -y install sysv-rc-conf 
apt-get -y install dnsutils 
apt-get -y install bc 
apt-get -y install nethogs
apt-get -y install openvpn 
apt-get -y install vnstat 
apt-get -y install less 
apt-get -y install screen 
apt-get -y install psmisc 
apt-get -y install apt-file 
apt-get -y install whois 
apt-get -y install ptunnel 
apt-get -y install ngrep 
apt-get -y install mtr 
apt-get -y install git 
apt-get -y install zsh 
apt-get -y install mrtg 
apt-get -y install snmp 
apt-get -y install snmpd 
apt-get -y install snmp-mibs-downloader 
apt-get -y install unzip 
apt-get -y install unrar 
apt-get -y install rsyslog 
apt-get -y install debsums 
apt-get -y install rkhunter
apt-get -y install build-essential
apt-get -y --force-yes -f install libxml-parser-perl

# disable exim
service exim4 stop
sysv-rc-conf exim4 off

# update apt-file
apt-file update

# setting vnstat
vnstat -u -i $ether
vnstat -i $ether
service vnstat restart

# install neofetch
echo "deb http://dl.bintray.com/dawidd6/neofetch jessie main" | sudo tee -a /etc/apt/sources.list
curl -L "https://bintray.com/user/downloadSubjectPublicKey?username=bintray" -o Release-neofetch.key && sudo apt-key add Release-neofetch.key && rm Release-neofetch.key
apt-get update
apt-get install neofetch

echo "clear" >> .bashrc
echo 'echo -e "WELCOME VPS PREMIUM $HOSTNAME"' >> .bashrc
echo 'echo -e "Script By ZHANGZI-MANIA"' >> .bashrc
echo 'echo -e "Ketik menu untuk menampilkan daftar perintah"' >> .bashrc
echo 'echo -e ""' >> .bashrc

# install webserver
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/nginx.conf"
mkdir -p /home/vps/public_html
echo "<pre>Welcome webserver kopet mania</pre>" > /home/vps/public_html/index.html
wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/vps.conf"
sed -i 's/listen = \/var\/run\/php5-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php5/fpm/pool.d/www.conf
service php5-fpm restart
service nginx restart

# install openvpn
wget -O /etc/openvpn/openvpn.tar "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/openvpn-debian.tar"
cd /etc/openvpn/
tar xf openvpn.tar
wget -O /etc/openvpn/1194.conf "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/1194.conf"
service openvpn restart
sysctl -w net.ipv4.ip_forward=1
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
iptables -t nat -I POSTROUTING -s 192.168.100.0/24 -o eth0 -j MASQUERADE
iptables-save > /etc/iptables_yg_baru_dibikin.conf
wget -O /etc/network/if-up.d/iptables "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/iptables"
chmod +x /etc/network/if-up.d/iptables
service openvpn restart

#konfigurasi openvpn
cd /etc/openvpn/
wget -O /etc/openvpn/client.ovpn "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/client-1194.conf"
sed -i $MYIP2 /etc/openvpn/client.ovpn;
cp client.ovpn /home/vps/public_html/

cd
# install badvpn
wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/badvpn-udpgw"
if [ "$OS" == "x86_64" ]; then
  wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/badvpn-udpgw64"
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300

# install mrtg
#apt-get update;apt-get -y install snmpd;
wget -O /etc/snmp/snmpd.conf "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/snmpd.conf"
wget -O /root/mrtg-mem "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/mrtg-mem.sh"
chmod +x /root/mrtg-mem
cd /etc/snmp/
sed -i 's/TRAPDRUN=no/TRAPDRUN=yes/g' /etc/default/snmpd
service snmpd restart
snmpwalk -v 1 -c public localhost 1.3.6.1.4.1.2021.10.1.3.1
mkdir -p /home/vps/public_html/mrtg
cfgmaker --zero-speed 100000000 --global 'WorkDir: /home/vps/public_html/mrtg' --output /etc/mrtg.cfg public@localhost
curl "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/mrtg.conf" >> /etc/mrtg.cfg
sed -i 's/WorkDir: \/var\/www\/mrtg/# WorkDir: \/var\/www\/mrtg/g' /etc/mrtg.cfg
sed -i 's/# Options\[_\]: growright, bits/Options\[_\]: growright/g' /etc/mrtg.cfg
indexmaker --output=/home/vps/public_html/mrtg/index.html /etc/mrtg.cfg
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
cd

# setting port ssh
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 143' /etc/ssh/sshd_config
sed -i 's/#Banner/Banner/g' /etc/ssh/sshd_config
service ssh restart

# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=777/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 442 -p 80 -b /etc/issue.net"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
service ssh restart
service dropbear restart

# bannerssh
wget "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/bannerssh"
mv ./bannerssh /bannerssh
chmod 0644 /bannerssh
service dropbear restart
service ssh restart

# upgade dropbear 2017.75
apt-get install zlib1g-dev
wget https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/dropbear-2017.75.tar.bz2
bzip2 -cd dropbear-2017.75.tar.bz2 | tar xvf -
cd dropbear-2017.75
./configure
make && make install
mv /usr/sbin/dropbear /usr/sbin/dropbear.old
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
cd && rm -rf dropbear-2017.75 && rm -rf dropbear-2017.75.tar.bz2

# install vnstat gui
cd /home/vps/public_html/
wget https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/vnstat_php_frontend-1.5.1.tar.gz
tar xf vnstat_php_frontend-1.5.1.tar.gz
rm vnstat_php_frontend-1.5.1.tar.gz
mv vnstat_php_frontend-1.5.1 vnstat
cd vnstat
sed -i "s/eth0/$ether/g" config.php
sed -i "s/\$iface_list = array('venet0', 'sixxs');/\$iface_list = array($ether);/g" config.php
sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
sed -i 's/Internal/Internet/g' config.php
sed -i '/SixXS IPv6/d' config.php
cd

# block all port except
sed -i '$ i\iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -d 127.0.0.1 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 21 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 22 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 53 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 80 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 81 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 109 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 110 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 143 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 443 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 1194 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 3128 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 8000 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 8080 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 10000 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 55 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p udp -m udp --dport 2500 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p udp -m udp -j DROP' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp -j DROP' /etc/rc.local

# install fail2ban
apt-get -y install fail2ban;service fail2ban restart;

# install squid3
apt-get -y install squid3
wget -O /etc/squid3/squid.conf "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/squid3.conf"
sed -i $MYIP2 /etc/squid3/squid.conf;
service squid3 restart

# install webmin
cd
wget -O webmin-current.deb http://www.webmin.com/download/deb/webmin-current.deb
dpkg -i --force-all webmin-current.deb
apt-get -y -f install;
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
rm -f /root/webmin-current.deb
service webmin restart
service vnstat restart

# install pptp vpn
wget "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/pptp.sh"
chmod +x pptp.sh
./pptp.sh

# download script
cd
wget -O /usr/bin/benchmark "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/benchmark.sh"
wget -O /usr/bin/speedtest "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/speedtest.py"
wget -O /usr/bin/ps_mem "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/ps_mem.py"
#wget -O /etc/issue.net "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/banner"
wget -O /usr/bin/dropmon "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/dropmon.sh"
wget -O /usr/bin/menu "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/menu.sh"
wget -O /usr/bin/user-add "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/user-add.sh"
wget -O /usr/bin/user-add-vpn "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/user-add-vpn.sh"
wget -O /usr/bin/user-add-pptp "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/user-add-pptp.sh"
wget -O /usr/bin/user-expire "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/user-expire.sh"
wget -O /usr/bin/user-gen "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/user-gen.sh"
wget -O /usr/bin/user-limit "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/user-limit.sh"
wget -O /usr/bin/user-list "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/user-list.sh"
wget -O /usr/bin/user-login "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/user-login.sh"
wget -O /usr/bin/user-active-list "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/user-active-list.sh"
wget -O /usr/bin/user-renew "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/user-renew.sh"
wget -O /usr/bin/user-del "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/user-del.sh"
wget -O /usr/bin/user-pass "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/user-pass.sh"
wget -O /usr/bin/user-expire-list "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/user-expire-list.sh"
wget -O /usr/bin/user-banned "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/user-banned.sh"
wget -O /usr/bin/unbanned-user "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/unbanned-user.sh"
wget -O /usr/bin/delete-user-expire "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/delete-user-expire.sh"
echo "0 0 * * * root /usr/bin/user-expire" > /etc/cron.d/user-expire
echo "* * * * * service dropbear restart" > /etc/cron.d/dropbear
chmod +x /usr/bin/benchmark
chmod +x /usr/bin/speedtest
chmod +x /usr/bin/ps_mem
chmod +x /usr/bin/dropmon
chmod +x /usr/bin/menu
chmod +x /usr/bin/user-add
chmod +x /usr/bin/user-add-vpn
chmod +x /usr/bin/user-add-pptp
chmod +x /usr/bin/user-expire
chmod +x /usr/bin/user-gen
chmod +x /usr/bin/user-limit
chmod +x /usr/bin/user-list
chmod +x /usr/bin/user-login
chmod +x /usr/bin/user-active-list
chmod +x /usr/bin/user-renew
chmod +x /usr/bin/user-del
chmod +x /usr/bin/user-pass
chmod +x /usr/bin/user-expire-list
chmod +x /usr/bin/user-banned
chmod +x /usr/bin/unbanned-user
chmod +x /usr/bin/delete-user-expire

# swap ram
dd if=/dev/zero of=/swapfile bs=1024 count=4096k
# buat swap
mkswap /swapfile
# jalan swapfile
swapon /swapfile
#auto star saat reboot
wget https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/fstab
mv ./fstab /etc/fstab
chmod 644 /etc/fstab
sysctl vm.swappiness=10
#permission swapfile
chown root:root /swapfile 
chmod 0600 /swapfile
cd

#install stunnel ssl
apt-get update
apt-get upgrade
apt-get install stunnel4
wget -O /etc/stunnel/stunnel.conf "https://raw.githubusercontent.com/brantbell/wulandari/srie/repo/stunnel.conf"
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart

# finishing
chown -R www-data:www-data /home/vps/public_html
service cron restart
service nginx start
service php5-fpm start
service vnstat restart
service snmpd restart
service ssh restart
service dropbear restart
service fail2ban restart
service squid3 restart
service webmin restart
cd
rm -f /root/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# info
clear
echo "Fitur yang Tersedia" | tee log-install.txt
echo "=======================================================" | tee -a log-install.txt
echo "Service :" | tee -a log-install.txt
echo "---------" | tee -a log-install.txt
echo "OpenSSH  : 22, 143" | tee -a log-install.txt
echo "Dropbear&Ssl : 777, 442, 443" | tee -a log-install.txt
echo "Squid3   : 8080, 3128 (limit to IP $MYIP)" | tee -a log-install.txt
echo "OpenVPN  : TCP 1194 (client config : http://$MYIP:81/client.ovpn)"  | tee -a log-install.txt
echo "badvpn   : badvpn-udpgw port 7300" | tee -a log-install.txt
echo "nginx    : 81" | tee -a log-install.txt
echo "" | tee -a log-install.txt

echo "Tools :" | tee -a log-install.txt
echo "-------" | tee -a log-install.txt
echo "axel, bmon, htop, iftop, mtr, rkhunter, nethogs: nethogs $ether" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Script :" | tee -a log-install.txt

echo "--------" | tee -a log-install.txt
echo "  - menu (Menu Script VPS via Putty) :" | tee -a log-install.txt
echo "  - Buat Akun SSH/OpenVPN (user-add)" | tee -a log-install.txt
echo "  - Banned Akun Nakal (user-banned)" | tee -a log-install.txt
echo "  - Buka Kunci Akun Nakal (unbanned-user)" | tee -a log-install.txt
echo "  - Hapus Akun SSH/OpenVPN (user-del)" | tee -a log-install.txt
echo "  - Ganti Kata Sandi Akun SSH/OpenVPN (user-pass)" | tee -a log-install.txt
echo "  - Tambah Masa Aktif SSH/OpenVPN (user-renew)" | tee -a log-install.txt
echo "  - Generate SSH/OpenVPN (user-gen)" | tee -a log-install.txt
echo "  - Monitoring Dropbear (dropmon [PORT])" | tee -a log-install.txt
echo "  - Cek Login Dropbear, OpenSSH, PPTP VPN dan OpenVPN (user-login)" | tee -a log-install.txt
echo "  - Kill Multi Login Manual (1-2 Login) (user-limit [x])" | tee -a log-install.txt
echo "  - Daftar Akun Aktif (user-active-list)" | tee -a log-install.txt
echo "  - Daftar List User (user-list)" | tee -a log-install.txt
echo "  - Daftar Akun Kadaluwarsa (user-expire-list)" | tee -a log-install.txt
echo "  - Akun Kadaluwarsa (user-expire)" | tee -a log-install.txt
echo "  - Hapus Akun Kadaluwarsa (delete-user-expire)" | tee -a log-install.txt
echo "  - Memory Usage (ps-mem)" | tee -a log-install.txt
echo "  - Speedtest (speedtest --share)" | tee -a log-install.txt
echo "  - Benchmark (benchmark)" | tee -a log-install.txt
echo "  - Reboot Server" | tee -a log-install.txt
echo "" | tee -a log-install.txt

echo "Fitur lain :" | tee -a log-install.txt
echo "------------" | tee -a log-install.txt
echo "Webmin         : http://$MYIP:10000/" | tee -a log-install.txt
echo "vnstat         : http://$MYIP:81/vnstat/ (Cek Bandwith)" | tee -a log-install.txt
echo "MRTG           : http://$MYIP:81/mrtg/" | tee -a log-install.txt
echo "Timezone       : Asia/Jakarta (GMT +7)" | tee -a log-install.txt
echo "Fail2Ban       : [on]" | tee -a log-install.txt
echo "(D)DoS Deflate : [on]" | tee -a log-install.txt
echo "Block Torrent  : [off]" | tee -a log-install.txt
echo "IPv6           : [off]" | tee -a log-install.txt
echo "Auto Lock User Expire tiap jam 00:00" | tee -a log-install.txt
echo "Auto Reboot tiap jam 00:00" | tee -a log-install.txt
echo "" | tee -a log-install.txt

echo "Edited By ZHANG-ZI" | tee -a log-install.txt
echo "ADMIN WWW KOPET88.COM" | tee -a log-install.txt
echo "Internet Gratis Sak Lawase" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Log Instalasi --> /root/log-install.txt" | tee -a log-install.txt
echo "" | tee -a log-install.txt

echo "***************SETUP COMPLETED********************" | tee -a log-install.txt
echo "-----------SILAHKAN REBOOT VPS ANDA---------------" | tee -a log-install.txt
echo "==================================================" | tee -a log-install.txt
echo "=============Ketik reboot ENTER =================="  | tee -a log-install.txt
cd ~/
rm -f /root/mrtg-mem
rm -f /root/pptp.sh
rm -f /root/dropbear-2017.75.tar.bz2
rm -rf /root/dropbear-2017.75
rm -f /root/debian7.sh
