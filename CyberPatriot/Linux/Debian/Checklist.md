1. Readme
2. Forensics questions
3. Run script
	a. deb http://security.debian.org/ [CODENAME]/updates main contrib non-fre
	b. allow-guest=false
	c. Grub password (see below)
	d. panic=0 to GRUB_CMDLINE_LINUX
	e. Login (enable these) https://www.debian.org/doc/manuals/securing-debian-manual/ch04s11.en.html
		a. auth       required   pam_unix.so nullok (remove nullok)
		b. auth     requisite  pam_securetty.so
	f. Su (add these)
		a. session  required   pam_limits.so
		b. auth        requisite   pam_wheel.so group=wheel debug
	g. Common session (add this)
		a. session    optional     pam_tmpdir.so
4. Delete media
5. Check VISUDO dir
6. Services | service --status-all  netstat -tulpn  apt-get remove pure-ftpd
7. Firefox
8. Check the /etc/passwd file
	a. Look for any repeating UID or GID
	b. Make sure no programs have a /bin/sh or /bin/bash
	c. Only root should have a UID and GID of 0
9. Check the /etc/group file and manage the groups
	Add all the admins to the sudo and adm group 
10. Everything connected to the wanted services (perms, data, admin priv, users, config)
	a. File configs
	b. Readme
	c. File perms
11. Unwanted apps (dpkg, software center, share)
12. Plain text documents (ls -R)
13. Python backdoors


Lock Grub:
grub-mkpasswd-pbkdf2

cat << EOF 
set superusers="username" 
password_pbkdf2 username'key' 
EOF