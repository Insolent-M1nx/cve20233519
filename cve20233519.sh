#!/bin/bash

echo ""
echo ""
echo "-----------------------------------"
echo "| CVE-2023-3519 Citrix ADC Script |"
echo "|                        Joe Wood |"
echo "___________________________________"
echo ""
echo ""
echo "Checking for last build date..."
echo "_____________________________________________________"
build=$(shell ls -ll /var/nsinstall | grep "build")
echo ""
echo "The last recorded build is:"
echo "$build"
echo ""
echo ""

echo "Checking for edited files..."
echo "_____________________________________________________"
echo ""
shell find /var/vpn/ -type f -newermt {Timestamp der Installer Files +1} -exec ls -l {} \;
find /var/netscaler/logon/ -type f -newermt {Timestamp der Installer Files +1} -exec ls -l {} \;
find /var/python/ -type f -newermt {Timestamp der Installer Files +1} -exec ls -l {} \;
echo ""
echo ""

echo "Checking for edited files under the ns_gui context..."
echo "_____________________________________________________"
echo ""
shell find /netscaler/ns_gui/ -type f -name *.php -newermt {Timestamp der Installer Files +1} -exec ls -l {} \;
echo ""

echo "If the above ^^ has not been edited that is a good sign"
echo ""
echo ""

echo "Checking HTTP Error Log Files (.sh)..."
echo "_____________________________________________________"
echo ""
zgrep '\.sh' /var/log/httperror.log*
echo ""
echo ""

echo "Checking HTTP Error Log Files (.php)..."
echo "_____________________________________________________"
echo ""
zgrep '\.php' /var/log/httperror.log*
echo ""
echo ""

echo "Checking HTTP Error Log Files (.pl)..."
echo "_____________________________________________________"
echo ""
zgrep '\.pl' /var/log/httperror.log*
echo ""
echo ""

echo "Checking Shell Log Files..."
echo "_____________________________________________________"
echo ""
shell zgrep -E 'database.php|/flash/nsconfig/keys/updated|/flash/nsconfig/keys|/ns_gui/vpn|LDAPTLS_REQCERT|ldapsearch|openssl|/nsconfig/ns.conf|del /etc/auth.conf|cp /usr/bin/bash|.F1.key|.F2.key|nobody' /var/log/sh.log*
echo ""
echo ""

echo "Checking Bash Log Files..."
echo "_____________________________________________________"
echo ""
shell zgrep -E 'database.php|/flash/nsconfig/keys/updated|/flash/nsconfig/keys|/ns_gui/vpn|LDAPTLS_REQCERT|ldapsearch|openssl|/nsconfig/ns.conf|del /etc/auth.conf|cp /usr/bin/bash|.F1.key|.F2.key|nobody' /var/log/bash.log*
echo ""
echo ""

echo "Checking Log Files for Known IOCs..."
echo "_____________________________________________________"
echo ""
grep -v '127\.0\.0' /var/log/*.log | grep 'nc -l\|/etc/passwd\|/etc/shadow\|python -c\|curl\|\.php'
echo ""
echo ""

echo "Checking for Edited Files with SETUID Bit..."
echo "_____________________________________________________"
echo ""
find /var -perm -4000 -user root -not -path "/var/nslog/*" -newermt {Timestamp der Installer Files +1} -exec ls -l {} \;
echo ""
echo ""

echo "Checking for Processes Launched Under 'Nobody' User Context..."
echo "_____________________________________________________"
echo ""
shell ps aux | grep nobody | grep -v '/bin/httpd'
echo ""
echo ""

echo "Checking Crontab..."
echo "_____________________________________________________"
echo ""
shell grep '' /etc/crontab
echo ""
echo ""

echo "Checking Crontab for 'Nobody' User (This should return: 'No Crontab')..."
echo "_____________________________________________________"
echo ""
shell crontab -l -u nobody
echo ""
echo ""

echo "Checking if NSFSYNCD is disabled (HA)..."
echo "_____________________________________________________"
echo ""
shell ps aux | grep nsfsyncd
echo ""
echo ""

echo "Checking HTTP Access-VPN Log Files (Look for unknown resources)..."
echo "_____________________________________________________"
echo ""
shell zgrep -E -v 'CitrixReceiver' /var/log/httpaccess-vpn.log* | grep ' 200 '
echo ""
echo ""

echo "Checking Web Access From Headless Chrome (Look for unknown resources)..."
echo "_____________________________________________________"
echo ""
shell zgrep 'HeadlessChrome' /var/log/httpaccess-vpn.log*
echo ""
echo ""

echo "Checking NPPE Core Dumps (This directory should be empty)..."
echo "_____________________________________________________"
echo ""
shell ls -ll /var/core/1
echo ""
echo ""

echo "Checking for Python Scripts (Verify any entries)..."
echo "_____________________________________________________"
echo ""
shell ps -aux | grep python
echo ""
echo ""

echo "Checking for Perl  Scripts (Verify any entries)..."
echo "_____________________________________________________" 
echo ""
shell ps -aux | grep perl
echo ""
echo ""

echo "Checking for Crypto-Miners (No process should be at 100% besides NSPPE-xx)..."
echo "_____________________________________________________" 
echo ""
shell top -n 10
echo ""
echo ""
echo "END! Thanks for playing"








