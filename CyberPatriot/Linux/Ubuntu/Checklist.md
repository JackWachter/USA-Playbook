1. Readme
2. Forensics questions
3. Software and updates (/etc/apt/sources.list)
4. Run script
5. Change retries in common pass (retry=3 remember=5 minlen=16)
6.  allow-guest=false
7. Delete media
8. Check VISUDO dir
9. Services | service --status-all  netstat -tulpn  apt-get remove pure-ftpd
10. Firefox/Chrome
11. Check the /etc/passwd file
	a. Look for any repeating UID or GID
	b. Make sure no programs have a /bin/sh or /bin/bash
	c. Only root should have a UID and GID of 0
12. Check the /etc/group file and manage the groups
	Add all the admins to the sudo and adm group
13. Stickybits 
14. Sudoers files
15. Everything connected to the wanted services (perms, data, admin priv, users, config)
16. Unwanted apps (dpkg, software center, share)
17. Plain text documents (ls -R)
18. Python backdoors
