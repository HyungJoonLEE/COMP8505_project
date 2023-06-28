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
[open_UAV]
	sequence      = 51001, 51002, 51003
	seq_timeout   = 15
	command	      = /sbin/iptables -I INPUT -s %IP% -p tcp --sport 51000 -j DROP
	tcpflags      = syn
[close_UAV]
	sequence      =	51003, 51002, 51001
  seq_timeout   =	15
  command       =	/sbin/iptables -D INPUT -s %IP% -p tcp --sport 51000 -j DROP
  tcpflags      =	syn"




echo "$setting" | sudo tee /etc/knockd.conf > /dev/null
systemctl restart knockd.service
