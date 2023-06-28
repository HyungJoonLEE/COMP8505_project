#!/bin/bash
dnf install knock -y
dnf install knock-server -y
touch /var/log/knockd.log
interface=$(ip -o link show | awk -F': ' '{if ($3 != "lo" && length($2) == 4) print $2}' | head -n 1)

sysconfig_setting="OPTIONS=\"-i "$interface"\"
START KNOCKD = 1"

echo "$sysconfig_setting" | sudo tee /etc/sysconfig/knockd > /dev/null

setting="[options]
	UseSyslog
  logfile = /var/log/knockd.log
	interface = "$interface"
[CLOSE_ATF]
	sequence      = 15003, 15002, 15001
	seq_timeout   = 15
	command	      = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 15000 -j ACCEPT
	tcpflags      = syn
[OPEN_ATF]
	sequence      =	15001, 15002, 15003
  seq_timeout   =	15
  command       =	/sbin/iptables -D INPUT -s %IP% -p tcp --dport 15000 -j ACCEPT
  tcpflags      =	syn"




echo "$setting" | sudo tee /etc/knockd.conf > /dev/null
systemctl restart knockd.service
