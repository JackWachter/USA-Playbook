#!/bin/bash  
doStart() {  
echo "IF YOU ARE NOT READY TO START PRESS, CTRL + C"    
# Debian stuff
dpkg -S `readlink -f /vmlinuz`
echo "linux-image-5.10.0-26-amd64: /boot/vmlinuz-5.10.0-26-amd64"
sleep 2
echo "onenote"
sleep 1
nano /etc/apt/sources.list
apt install -y unattended-upgrades
systemctl enable unattended-upgrades
systemctl start unattended-upgrades
apt install -y apt-config-auto-update -y
dpkg-reconfigure --priority=low unattended-upgrades
nano /etc/apt/apt.conf.d/50unattended-upgrades
touch /etc/apt/apt.conf.d/20auto-upgrades
sed -i -e '$a\'$'\n''APT::Periodic::Update-Package-Lists "1";' /etc/apt/apt.conf.d/20auto-upgrades
sed -i -e '$a\'$'\n''APT::Periodic::Unattended-Upgrade "1";' /etc/apt/apt.conf.d/20auto-upgrades
sed -i -e '$a\'$'\n''APT::Periodic::AutocleanInterval "7";' /etc/apt/apt.conf.d/20auto-upgrades
grub-mkpasswd-pbkdf2
sleep 10
nano /etc/grub.d/00_header
nano /etc/default/grub
update-grub
chmod o-x /sbin/shutdown
chmod o-x /sbin/reboot
chmod  o-x /bin/systemctl
Games
}  

#Backups  
doBackups () {  
echo "********BACKUPS********"  
mkdir /Backups  
chmod 644 /Backups  
cp --backup /etc/sudoers /Backups  
cp --backup /etc/passwd /Backups  
cp --backup /etc/shadow /Backups 
cp --backup /etc/apt/sources.list /Backups
Games 
}  

#Pam  
doPam () {  
echo "********PAM********"  
apt-get -y install libpam-cracklib  
apt-get -y install libpam-tmpdir
groupadd wheel
echo "Add admins to wheel!!"
sleep 2
nano /etc/group
nano /etc/pam.d/login
nano /etc/pam.d/su
nano /etc/pam.d/common-session
sed -i -e '$a\'$'\n''-:wheel:ALL EXCEPT LOCAL' /etc/security/access.conf
touch /etc/pam.d/other
echo '  auth     required       pam_securetty.so
  auth     required       pam_unix_auth.so
  auth     required       pam_warn.so
  auth     required       pam_deny.so
  account  required       pam_unix_acct.so
  account  required       pam_warn.so
  account  required       pam_deny.so
  password required       pam_unix_passwd.so
  password required       pam_warn.so
  password required       pam_deny.so
  session  required       pam_unix_session.so
  session  required       pam_warn.so
  session  required       pam_deny.so' > /etc/pam.d/other

# Configure Password Aging Controls  
sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS   90' /etc/login.defs  
sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS   10'  /etc/login.defs  
sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE   7' /etc/login.defs  
sed -i '/^FAILLOG_ENAB/ c\FAILLOG_ENAB   yes' /etc/login.defs  
sed -i '/^LOG_UNKFAIL_ENAB/ c\LOG_UNKFAIL_ENAB   yes' /etc/login.defs  
sed -i '/^SYSLOG_SU_ENAB/ c\SYSLOG_SU_ENAB   yes' /etc/login.defs  
sed -i '/^SYSLOG_SG_ENAB/ c\SYSLOG_SG_ENAB   yes' /etc/login.defs 
sed -i '/^ENCRYPT_METHOD/ c\ENCRYPT_METHOD   SHA512' /etc/login.defs
nano /etc/login.defs

# Force Strong Passwords  
sudo sed -i -e 's/difok=3\+/difok=3 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1/' /etc/pam.d/common-password  
sudo sed -i -e 's/sha512\+/sha512 remember=5 minlen=16/' /etc/pam.d/common-password  
#password        [success=1 default=ingore]      pam_unix.so obscure use_authtok try_first_pass sha512 remember=5 minlen=8  
#password        requisite       pam_cracklib.so retry=5 minlen=16 difok=3 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1  
nano /etc/pam.d/common-password  
Games 
}  

#Users 
doUsers () {  
echo "********USERS********"  
        PASS="Th1sIs@G00dPass!" 
        #remove keylogger before doing password stuff 
        apt purge -y logkeys* 
        #Get all users and uids from passwd and put them into seperate files 
        cut -d: -f1 /etc/passwd > /Backups/usrs.txt 
        cut -d: -f3 /etc/passwd > /Backups/uids.txt 
        #convert ^ files into arrays 
        all_usrs=() 
        all_uids=() 
        users=() 
        for i in $(cat /Backups/usrs.txt); do 
          all_usrs+=($i) 
        done 
  
        for i in $(cat /Backups/uids.txt); do 
          all_uids+=($i) 
        done 

        #loop through uids for ones that are 0 or >1000 
        for i in ${!all_uids[@]}; do 
          if [ ${all_uids[$i]} -eq 0 ] || [ ${all_uids[$i]} -ge 1000 ]; 
          then 
            users+=(${all_usrs[$i]}) 
          fi 
        done 

        #ask if the user needs to be a user or admin 
        admins=() 
        for i in ${!users[@]}; do 
          printf "Do u wish to curb stomp ${users[$i]}: " 
          read answer 
          if [ $answer == 'y' ]; 
          then 
            userdel ${users[i]} 
            echo "Casey used ginger" 
            echo "${users[$i]} died" 
          else 
            echo -e "$PASS\n$PASS" | passwd ${users[$i]} 
            printf "What is this users power level: " 
            read answer 
            if [ $answer == 'a' ]; 
            then 
              admins+="${users[$i]}," 
              echo "${users[$i]} is now a fucking god" 
            else 
              echo "${users[$i]} is now a useless user" 
            fi 
          fi 
        done 
        sed -i "/sudo:x:27:/c\sudo:x:27:${admins[0]}" /etc/group 
echo "CHECK FOR HIDDEN USERS" 
nano /etc/shadow 
nano /etc/passwd   
        Games 
} 

  

#Visudo 
doVisudo() { 
visudo 
echo -n "Replace all? '(y/n)' : "  
read viSudo 
if [ $viSudo = "y" ]; then   
        echo '#
        # This file MUST be edited with the 'visudo' command as root.
        #
        # Please consider adding local content in /etc/sudoers.d/ instead of
        # directly modifying this file.
        #
        # See the man page for details on how to write a sudoers file.
        #
        Defaults	env_reset
        Defaults	mail_badpass
        Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

        # Host alias specification

        # User alias specification

        # Cmnd alias specification

        # User privilege specification
        root	ALL=(ALL:ALL) ALL

        # Allow members of group sudo to execute any command
        %sudo	ALL=(ALL:ALL) ALL

        # See sudoers(5) for more information on "@include" directives:

        @includedir /etc/sudoers.d' > /etc/sudoers 

        echo '# 
        # As of Debian version 1.7.2p1-1, the default /etc/sudoers file created on 
        # installation of the package now includes the directive: 
        #  
        #       #includedir /etc/sudoers.d 
        #  
        # This will cause sudo to read and parse any files in the /etc/sudoers.d  
        # directory that do not end in '~' or contain a '.' character. 
        #  
        # Note that there must be at least one file in the sudoers.d directory (this 
        # one will do), and all files in this directory should be mode 0440. 
        #  
        # Note also, that because sudoers contents can vary widely, no attempt is  
        # made to add this directive to existing sudoers files on upgrade.  Feel free 
        # to add the above directive to the end of your /etc/sudoers file to enable  
        # this functionality for existing installations if you wish! 
        # 
        # Finally, please note that using the visudo command is the recommended way 
        # to update sudoers content, since it protects against many failure modes. 
        # See the man page for visudo for more information. 
        #' > /etc/sudoers.d/README 

else  
echo "Not replaced"  
fi 
        echo '# Allow snap-provided applications to work with sudo 
        Defaults    secure_path += /snap/bin' > /etc/sudoers.d/99-snapd.conf   
        Games 
} 

  

  

#Firewall  
doFirewall () {  
echo "********FIREWALL********"  
apt-get -y install ufw  
ufw enable 
ufw logging HIGH  
ufw default deny  
ports=() 
printf "How many ports to allow: " 
read portNum 
for i in $(seq 1 $portNum); do 
printf "Enter port: " 
read answer 
ufw allow $answer 
done 
Games 
}  
#Malware  
doMalware () {  
echo "********MALWARE********"  
sudo apt-get -y purge hydra*  
sudo apt-get -y purge john*  
sudo apt-get -y purge gcc* 
sudo apt-get -y purge nikto*  
sudo apt-get -y purge nmap*  
sudo apt-get -y purge zenmap*  
sudo apt-get -y purge freeciv-server*  
sudo apt-get -y purge samba-common*  
sudo apt-get -y purge ophcrack*  
sudo apt-get -y purge wireshark*  
sudo apt-get -y purge aircrack*  
sudo apt-get -y purge ettercap*  
sudo apt-get -y purge rpc* 
sudo apt-get -y purge freeciv*  
sudo apt-get -y purge ftpscan* 
sudo apt-get -y purge nbtscan*  
sudo apt-get -y purge freeciv-*  
sudo apt-get -y purge wireshark*  
sudo apt-get -y purge tftpd-hpa* 
sudo apt-get -y purge x11vnc* 
sudo apt-get -y purge sendmail* 
sudo apt-get -y purge xinetd*  
sudo apt-get -y purge snmp*  
sudo apt-get -y autoremove --purge logkeys*  
sudo apt-get -y autoremove --purge ophcrack-cli*  
sudo apt-get -y remove telnetd*  
sudo apt-get -y remove nis*  
sudo apt-get -y remove bind9*  
sudo apt-get –y remove yersinia*  
sudo apt-get -y purge minetest*  
sudo apt-get -y purge minetest-*  
sudo apt-get -y purge pyrdp* 
sudo apt-get -y purge themole* 
sudo apt-get -y purge metasploit-framework* 
sudo apt-get -y purge theharvester* 
sudo apt-get -y purge aircrack-ng* 
sudo apt-get -y purge burpsuite* 
sudo apt-get -y purge sqlninja* 
sudo apt-get -y purge ettercap* 
sudo apt-get -y purge fimap*
sudo apt-get -y purge hashcat* 
sudo apt-get -y purge maltego* 
sudo apt-get -y purge owasp-zap* 
sudo apt-get -y purge wapiti* 
sudo apt-get -y purge whatweb* 
sudo apt-get -y purge zenmap* 
sudo apt-get -y purge xsser* 
sudo apt-get -y purge beef-xss* 
sudo apt-get -y purge cisco-torch* 
sudo apt-get -y purge jboss-autopwn* 
sudo apt-get -y purge maltego-teeth* 
sudo apt-get -y purge shellnoob* 
sudo apt-get -y purge sqlninja* 
sudo apt-get -y purge thc-ipv6* 
sudo apt-get -y purge goldeneye* 
sudo apt-get -y purge pompem* 
#sudo apt-get -y remove rsh-server*  
sudo apt-get -y purge telnet* 
Games 
}  
  
#Services  
doServices () {  
echo "********SERVICES********"  
echo -n "Delete ftp? '(y/n)' : "  
read ftpd  
if [ $ftpd = "y" ]; then  
echo "Deleting ftp"  
sudo apt-get -y purge ftp  
else  
echo "ftp not deleted"  
nano /etc/ftpusers
if [ -e /etc/vsftpd.conf ]; then  
nano /etc/vsftpd.conf  
fi 
if [ -e /etc/vsftpd.conf ]; then  
nano /etc/vsftpd/vsftpd.conf  
fi  
fi  
echo -n "Delete apache2? '(y/n)' : "  
read apached  
if [ $apached = "y" ]; then  
echo "deleting apache2"  
sudo apt-get -y purge apache2  
else  
echo "apache2 NOT deleted"  
nano /etc/apache2/apache2.conf  
fi  
echo -n "Delete samba? '(y/n)' : "  
read smbd  
if [ $smbd = "y" ]; then  
sudo apt-get -y purge samba*  
fi 
echo -n "Delete telnet? '(y/n)' : "  
read telnetde  
if [ $telnetde = "y" ]; then  
sudo apt-get -y purge telnetd*  
fi  
Games 
}  
  
#Media  
doMedia () {  
echo "********MEDIA********"  
find /home -name "*.mp3" -type f >> music.txt  
find /home -name "*.mov" -type f >> music.txt  
find /home -name "*.mp4" -type f >> music.txt  
find /home -name "*.gif" -type f >> music.txt  
find /home -name "*.png" -type f >> music.txt  
find /home -name "*.jpg" -type f >> music.txt  
find /home -name "*.jpeg" -type f >> music.txt  
find /home -name "*.avi" -type f >> music.txt  
find /home -name "*.mpg" -type f >> music.txt  
find /home -name "*.mpeg" -type f >> music.txt  
find /home -name "*.flac" -type f >> music.txt  
find /home -name "*.flv" -type f >> music.txt  
find /home -name "*.ogg" -type f >> music.txt  
find /home -name "*.txt" -type f >> music.txt  

#Extra Media  
find / -name "*.mp3" -type f >> music2.txt  
find / -name "*.mov" -type f >> music2.txt  
find / -name "*.mp4" -type f >> music2.txt  
find / -name "*.gif" -type f >> music2.txt  
find / -name "*.png" -type f >> music2.txt  
find / -name "*.jpg" -type f >> music2.txt  
find / -name "*.jpeg" -type f >> music2.txt  

#Other  
sudo netstat -tulpn >> netstat.txt  
cat /etc/group | grep "root" >> fuck_ups.txt  
cat /etc/group | grep "adm" >> fuck_ups.txt  
cat /etc/group | grep "sudo" >> fuck_ups.txt  
cat /etc/group | grep "users" >> fuck_ups.txt  
cat /etc/group | grep "nopasswdlogin" >> fuck_ups.txt  
touch ps.txt  
ps aux > /root/psAux  
Games 
}  
  
#Sysctl  
doSysctl () {  
echo "********SYSCTL********"  
echo "  
# Kernel sysctl configuration file for Linux 
# 
# Version 1.14 - 2019-04-05 
# Michiel Klaver - IT Professional 
# http://klaver.it/linux/ for the latest version - http://klaver.it/bsd/ for a BSD variant 
# 
# This file should be saved as /etc/sysctl.conf and can be activated using the command: 
# sysctl -e -p /etc/sysctl.conf 
# 
# For binary values, 0 is disabled, 1 is enabled.  See sysctl(8) and sysctl.conf(5) for more details. 
# 
# Tested with: Ubuntu 14.04 LTS kernel version 3.13 
#              Debian 7 kernel version 3.2 
#              CentOS 7 kernel version 3.10 
  

# 
# Intended use for dedicated server systems at high-speed networks with loads of RAM and bandwidth available 
# Optimised and tuned for high-performance web/ftp/mail/dns servers with high connection-rates 
# DO NOT USE at busy networks or xDSL/Cable connections where packetloss can be expected 
# ---------- 
  
# Credits: 
# http://www.enigma.id.au/linux_tuning.txt 
# http://www.securityfocus.com/infocus/1729 
# http://fasterdata.es.net/TCP-tuning/linux.html 
# http://fedorahosted.org/ktune/browser/sysctl.ktune 
# http://www.cymru.com/Documents/ip-stack-tuning.html 
# http://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt 
# http://www.frozentux.net/ipsysctl-tutorial/chunkyhtml/index.html 
# http://knol.google.com/k/linux-performance-tuning-and-measurement 
# http://www.cyberciti.biz/faq/linux-kernel-tuning-virtual-memory-subsystem/ 
# http://www.redbooks.ibm.com/abstracts/REDP4285.html 
# http://www.speedguide.net/read_articles.php?id=121 
# http://lartc.org/howto/lartc.kernel.obscure.html 
# http://en.wikipedia.org/wiki/Sysctl 
# https://blog.cloudflare.com/http-2-prioritization-with-nginx/ 
  

### 
### GENERAL SYSTEM SECURITY OPTIONS ### 
### 
  
# Controls the System Request debugging functionality of the kernel 
kernel.sysrq = 0 
  
# Controls whether core dumps will append the PID to the core filename. 
# Useful for debugging multi-threaded applications. 
kernel.core_uses_pid = 1 
  
#Allow for more PIDs 
kernel.pid_max = 65535 
  
# The contents of /proc/<pid>/maps and smaps files are only visible to 
# readers that are allowed to ptrace() the process 
kernel.maps_protect = 1 
  
#Enable ExecShield protection 
kernel.exec-shield = 1 
kernel.randomize_va_space = 2 
  
# Controls the maximum size of a message, in bytes 
kernel.msgmnb = 65535 
  
# Controls the default maxmimum size of a mesage queue 
kernel.msgmax = 65535 
  
# Restrict core dumps 
fs.suid_dumpable = 0 
  
# Hide exposed kernel pointers 
kernel.kptr_restrict = 1 
  

### 
### IMPROVE SYSTEM MEMORY MANAGEMENT ### 
### 
  
# Increase size of file handles and inode cache 
fs.file-max = 209708 
  
# Do less swapping 
vm.swappiness = 30 
vm.dirty_ratio = 30 
vm.dirty_background_ratio = 5 
# specifies the minimum virtual address that a process is allowed to mmap 
vm.mmap_min_addr = 4096 
 
# 50% overcommitment of available memory 
vm.overcommit_ratio = 50 
vm.overcommit_memory = 0 
 
# Set maximum amount of memory allocated to shm to 256MB 
kernel.shmmax = 268435456 
kernel.shmall = 268435456

# Keep at least 64MB of free RAM space available 
vm.min_free_kbytes = 65535 


### 
### GENERAL NETWORK SECURITY OPTIONS ### 
### 
  
#Prevent SYN attack, enable SYNcookies (they will kick-in when the max_syn_backlog reached) 
net.ipv4.tcp_syncookies = 1 
net.ipv4.tcp_syn_retries = 2 
net.ipv4.tcp_synack_retries = 2 
net.ipv4.tcp_max_syn_backlog = 4096 
  
# Disables packet forwarding 
net.ipv4.ip_forward = 0 
net.ipv4.conf.all.forwarding = 0 
net.ipv4.conf.default.forwarding = 0 
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0 

# Disables IP source routing 
net.ipv4.conf.all.send_redirects = 0 
net.ipv4.conf.default.send_redirects = 0 
net.ipv4.conf.all.accept_source_route = 0 
net.ipv4.conf.default.accept_source_route = 0 
net.ipv6.conf.all.accept_source_route = 0 
net.ipv6.conf.default.accept_source_route = 0 
  
# Enable IP spoofing protection, turn on source route verification 
net.ipv4.conf.all.rp_filter = 1 
net.ipv4.conf.default.rp_filter = 1 
  
# Disable ICMP Redirect Acceptance 
net.ipv4.conf.all.accept_redirects = 0 
net.ipv4.conf.default.accept_redirects = 0 
net.ipv4.conf.all.secure_redirects = 0 
net.ipv4.conf.default.secure_redirects = 0 
net.ipv6.conf.all.accept_redirects = 0 
net.ipv6.conf.default.accept_redirects = 0 
  
# Enable Log Spoofed Packets, Source Routed Packets, Redirect Packets 
net.ipv4.conf.all.log_martians = 1 
net.ipv4.conf.default.log_martians = 1 
  
# Decrease the time default value for tcp_fin_timeout connection 
net.ipv4.tcp_fin_timeout = 7 
  
# Decrease the time default value for connections to keep alive 
net.ipv4.tcp_keepalive_time = 300 
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15 
  
# Don't relay bootp 
net.ipv4.conf.all.bootp_relay = 0 
  
# Don't proxy arp for anyone 
net.ipv4.conf.all.proxy_arp = 0 
  
# Turn on the tcp_timestamps, accurate timestamp make TCP congestion control algorithms work better 
net.ipv4.tcp_timestamps = 1 
  
# Don't ignore directed pings 
net.ipv4.icmp_echo_ignore_all = 0 
  
# Enable ignoring broadcasts request 
net.ipv4.icmp_echo_ignore_broadcasts = 1 
  
# Enable bad error message Protection 
net.ipv4.icmp_ignore_bogus_error_responses = 1 
  
# Allowed local port range 
net.ipv4.ip_local_port_range = 16384 65535 
  
# Enable a fix for RFC1337 - time-wait assassination hazards in TCP 
net.ipv4.tcp_rfc1337 = 1 

# Do not auto-configure IPv6 
net.ipv6.conf.all.autoconf=0 
net.ipv6.conf.all.accept_ra=0 
net.ipv6.conf.default.autoconf=0 
net.ipv6.conf.default.accept_ra=0 
net.ipv6.conf.eth0.autoconf=0 
net.ipv6.conf.eth0.accept_ra=0 
 

### 
### TUNING NETWORK PERFORMANCE ### 
### 
  
# Use BBR TCP congestion control and set tcp_notsent_lowat to 16384 to ensure HTTP/2 prioritization works optimally 
# Do a 'modprobe tcp_bbr' first (kernel > 4.9) 
# Fall-back to htcp if bbr is unavailable (older kernels) 
net.ipv4.tcp_congestion_control = htcp 
net.ipv4.tcp_congestion_control = bbr 
net.ipv4.tcp_notsent_lowat = 16384 
     
# For servers with tcp-heavy workloads, enable 'fq' queue management scheduler (kernel > 3.12) 
net.core.default_qdisc = fq 
  
# Turn on the tcp_window_scaling 
net.ipv4.tcp_window_scaling = 1 
  
# Increase the read-buffer space allocatable 
net.ipv4.tcp_rmem = 8192 87380 16777216 
net.ipv4.udp_rmem_min = 16384 
net.core.rmem_default = 262144 
net.core.rmem_max = 16777216 
  
# Increase the write-buffer-space allocatable 
net.ipv4.tcp_wmem = 8192 65536 16777216 
net.ipv4.udp_wmem_min = 16384 
net.core.wmem_default = 262144 
net.core.wmem_max = 16777216 
  
# Increase number of incoming connections 
net.core.somaxconn = 32768 
  
# Increase number of incoming connections backlog 
net.core.netdev_max_backlog = 16384 
net.core.dev_weight = 64 
  
# Increase the maximum amount of option memory buffers 
net.core.optmem_max = 65535 
  
# Increase the tcp-time-wait buckets pool size to prevent simple DOS attacks 
net.ipv4.tcp_max_tw_buckets = 1440000 
# try to reuse time-wait connections, but don't recycle them (recycle can break clients behind NAT) 
net.ipv4.tcp_tw_recycle = 0 
net.ipv4.tcp_tw_reuse = 1 

# Limit number of orphans, each orphan can eat up to 16M (max wmem) of unswappable memory 
net.ipv4.tcp_max_orphans = 16384 
net.ipv4.tcp_orphan_retries = 0 
  
# Limit the maximum memory used to reassemble IP fragments (CVE-2018-5391) 
net.ipv4.ipfrag_low_thresh = 196608 
net.ipv6.ip6frag_low_thresh = 196608 
net.ipv4.ipfrag_high_thresh = 262144 
net.ipv6.ip6frag_high_thresh = 262144 
  
  
# don't cache ssthresh from previous connection 
net.ipv4.tcp_no_metrics_save = 1 
net.ipv4.tcp_moderate_rcvbuf = 1 
# Increase size of RPC datagram queue length 
net.unix.max_dgram_qlen = 50 
  
# Don't allow the arp table to become bigger than this 
net.ipv4.neigh.default.gc_thresh3 = 2048 
  
# Tell the gc when to become aggressive with arp table cleaning. 
# Adjust this based on size of the LAN. 1024 is suitable for most /24 networks 
net.ipv4.neigh.default.gc_thresh2 = 1024 
  
# Adjust where the gc will leave arp table alone - set to 32. 
net.ipv4.neigh.default.gc_thresh1 = 32 
  
# Adjust to arp table gc to clean-up more often 
net.ipv4.neigh.default.gc_interval = 30 
  
# Increase TCP queue length 
net.ipv4.neigh.default.proxy_qlen = 96 
net.ipv4.neigh.default.unres_qlen = 6 
  
# Enable Explicit Congestion Notification (RFC 3168), disable it if it doesn't work for you 
net.ipv4.tcp_ecn = 1 
net.ipv4.tcp_reordering = 3 
  
# How many times to retry killing an alive TCP connection 
net.ipv4.tcp_retries2 = 15 
net.ipv4.tcp_retries1 = 3 
  
# Avoid falling back to slow start after a connection goes idle 
# keeps our cwnd large with the keep alive connections (kernel > 3.6) 
net.ipv4.tcp_slow_start_after_idle = 0
  
# Allow the TCP fastopen flag to be used, beware some firewalls do not like TFO! (kernel > 3.7) 
net.ipv4.tcp_fastopen = 3 
  
# This will enusre that immediatly subsequent connections use the new values 
net.ipv4.route.flush = 1 
net.ipv6.route.flush = 1 
  
  
### 
### Comments/suggestions/additions are welcome! 
### 
" > /etc/sysctl.conf  
sysctl -p  
sysctl -w kernel.dmesg_restrict=1 
Games 
}  
  
#lightdm 
doLightdm () {  
echo "********GUEST ACCOUNT********"  
# Disable Guest Account  
apt-get install lightdm  
echo allow-guest=false
sleep 2  
#allow-guest=false 
#Ubuntu 16  
nano /etc/lightdm/lightdm.conf  
#Ubuntu 18  
nano /etc/lightdm/lightdm.conf.d  
sleep 4  
echo "*****LOOK FOR HIDDEN USERS IN THESE FILES*****"  
sleep 5  
nano /etc/lightdm/lightdm.conf  
nano /etc/lightdm/users.conf  
Games 
} 
#SSH  
doSsh () {  
echo "********SSH********"  
echo -n "secure ssh? '(y/n)'"  
read sshs  
if [ $sshs = "y" ]; then  
sudo apt install openssh-server  
sleep 3  
echo "Port 22  
Protocol 2  
HostKey /etc/ssh/ssh_host_rsa_key  
HostKey /etc/ssh/ssh_host_dsa_key  
HostKey /etc/ssh/ssh_host_ecdsa_key  
HostKey /etc/ssh/ssh_host_ed25519_key  
UsePrivilegeSeparation yes  
KeyRegenerationInterval 3600  
ServerKeyBits 1024  
SyslogFacility AUTH  
LogLevel INFO  
LoginGraceTime 120  
MaxAuthTries 4  
LoginGraceTime 60  
PermitRootLogin no  
ClientAliveInterval 300  
ClientAliveCountMax 0  
PermitUserEnvironment no  
UseDNS no  
MaxSessions 2  
StrictModes yes  
RSAAuthentication yes  
PubkeyAuthentication yes  
IgnoreRhosts yes  
RhostsRSAAuthentication no  
HostbasedAuthentication no  
PermitEmptyPasswords no  
ChallengeResponseAuthentication no  
X11Forwarding no  
X11DisplayOffset 10  
Banner none  
PrintMotd no  
PrintLastLog yes  
TCPKeepAlive yes  
AcceptEnv LANG LC_*  
UsePAM yes  
Ciphers aes128-ctr,aes192-ctr,aes256-ctr  
MACs hmac-sha2-256,hmac-sha2-512  
PermitUserEnvironment no  
PrintLastLog yes  
ClientAliveInterval 600  
IgnoreUserKnownHosts yes  
Compression no" > /etc/ssh/sshd_config  

systemctl restart sshd  
systemctl status sshd  
else  
echo "ssh not configured"  
sleep 3  
echo -n "Remove ssh? '(y/n)'"  
read rems  
if [ $rems = "y" ]; then  
echo "REMOVE SSH"  
apt-get remove openssh-server  
else  
sleep 3  
fi  
fi  
service ssh restart  
service ssh start  
chmod 0644 /etc/ssh/*key.pub  
chmod 0600 /etc/ssh/ssh_host*key  
sed -i '$i -a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh' /etc/audit/audit.rules  
  
sed -i '$i -a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh' /etc/audit/audit.rules  
  
(echo -ne '\n'; echo 'y'; echo 'This1s@G00dPass'; echo 'This1s@G00dPass') | ssh-keygen -t rsa  
Games 
}  
  
#Perms  
doPerms () {  
echo "********PERMS********"  
chmod 644 /etc/passwd  
chmod 644 /etc/group  
chmod -R 0444 /var/www/html/  
chmod 644 /etc/fstab  
chmod 400 /etc/shadow  
chmod 02750 /bin/su  
chmod 644 /etc/profile  
chmod 0700 /etc/rc*  
chmod 0700 /etc/init.d*  
chmod 0700 /etc/sysctl.conf  
chmod 0700 /etc/hosts.allow  
chmod 0700 /etc/mtab  
chmod 0700 /etc/utab  
chmod 0700 /var/adm/wtmp  
chmod 0600 /etc/sysctl.conf  
chmod 0700 /etc/inittab  
chmod 1777 /tmp  
chmod og-rwx /boot/grub/grub.cfg  
chown root:root /boot/grub/grub.cfg  
chown root:root /etc/passwd  
chown root:root /etc/sudoers  
chown root:shadow /etc/shadow  
chown root:root /etc/group  
chown root:root /etc/fstab  
chown root:root /etc/group-  
chown root:root /etc/passwd-  
Games 
}  

#Crontabs  
doCrontabs () {  
echo "********CRONTAB********"  
crontab -e  
nano /etc/anacrontab  
nano /etc/cron.d/*  
nano /etc/cron.d/.*  
nano /var/spool/cron/crontabs/.*  
nano /var/spool/cron/crontabs/*  
Games 
}  
  
#Forkbombs  
doForkbombs () {  
echo "********FORKBOMBS********"  
echo "*    hard    nproc    nnn" >> /etc/security/limits.conf  
sed -i '$i tp hard nproc 300' /etc/security/limits.conf  
sed -i '$i @student hard nproc 50' /etc/security/limits.conf  
sed -i '$i @faculty soft nproc 100' /etc/security/limits.conf  
sed -i '$i @pusers hard nproc 200' /etc/security/limits.conf  
Games 
}  
  
#StickyBits  
doStickyBits () {  
echo "********STICKY-BITS********"  
sudo touch /root/sticky  
find / -xdev -type d \( -perm 0002 -a ! -perm -1000 \) -print >> /root/sticky  
Games 
}  


#MISC  
doMISC () {  
echo "********MISC********"  
#ASLR randomization  
touch /etc/sysctl.d/01-disable-aslr.conf  
echo "kernel.randomize_va_space = 0" >> /etc/sysctl.d/01-disable-aslr.conf  
#Log Martian Packets  
sed -i '$i net.ipv4.conf.all.log_martians=1' /etc/sysctl.conf  
sed -i '$i net.ipv4.conf.default.log_martians=1' /etc/sysctl.conf  
#sudo sed -i '$i set superusers=\"root\"\npassword_pbkdf2 root ' /etc/grub.d/40_custom  
#update-grub  
#sudo apt-get -y install apparmor  
#service apparmor restart  
#service apparmor start  

#Remove alias  
unalias -a  
#Audits  
sudo apt-get install auditd -y  
sudo auditctl -e 1   
sudo service auditd start   
Games  
}  
  
#Bashrc  
doBashrc () {  
echo "********BASH-RC********"  
    nano /root/.bashrc  
    nano /etc/bash.bashrc  
    nano /etc/profile  
    echo "LOOK IN YOUR BASHRC"  
    read myUserName  
    nano /home/$myUserName/.bashrc  
     Games  
}  

#Updates  
doUpdates () {  
echo "********UPDATES********"  
apt-get -y update  
apt-get -y upgrade  
echo "UPDATE KERNEL AFTER RESTART"   
Games  
}  

#Processes  
doProcesses () {  
echo "********Processes********"  
apt install -y net-tools 
touch /Backups/net.txt 
netstat -tulpn > /Backups/net.txt 
netstat -tulpn 
echo -n "Remove services? '(y/n)' : "  
read netRem 
if [ $netRem = "y" ]; then  
echo -n "Package name: " 
read netName 
apt purge -y $netName  
else  
echo "No packages removed" 
fi 

netstat -tulpn 
pids=() 
printf "How many pids to kill: " 
read pidNum 
for i in $(seq 1 $pidNum); do 
printf "Enter pid: " 
read pidAnswer 
kill -9 $pidAnswer 
done 
Games  
}  

#Optional 
doOptions () {  
echo "********OPTIONAL********"  
echo -n "Add users? '(y/n)' : "  
read adder 
if [ $adder = "y" ]; then  
echo -n "Username: " 
read adderName 
useradd -p $(openssl passwd -1 Password123456789!) $adderName  
else  
echo "No users added" 
fi 
echo -n "Add groups? '(y/n)' : "  
read mkGroup 
if [ $mkGroup = "y" ]; then  
echo -n "Group Name: " 
read mkNamer 
groupadd $mkNamer 
else  
echo "No users added" 
fi 
echo -n "Add user to group? '(y/n)' : " 
read grouper  
if [ $grouper = "y" ]; then 
echo -n "Username: " 
read grouperName 
echo -n "Group name: " 
read groupName 
usermod -a -G $groupName $grouperName 
else  
echo "No users added to groups" 
fi  
echo -n "Add packages? '(y/n)' : " 
read prog 
if [ $prog = "y" ]; then 
echo -n "Package Name: " 
read progName 
apt install -y $progName 
else  
echo "No packages installed" 
fi 
Games  
}  

# GET THIS BREAD  
function Games()  
{  
  games=("doStart" "doBackups" "doPam" "doUsers" "doVisudo" "doFirewall" "doMalware" "doServices" "doMedia" "doSysctl" "doLightdm" "doSsh" "doPerms" "doCrontabs" "doForkbombs" "doStickyBits" "doMISC" "doBashrc" "doUpdates" "doProcesses" "doOptions" )  
  for i in ${!games[@]}; do   
          echo "$i ${games[$i]}"  
  done  
  printf "Which game do u want to play: "  
  read answer  
  ${games[$answer]}  
}  
Games   