# Port Scanning

## NMAP

### Standard Port Scan

```bash
nmap <ip>
```

### Version and OS included

```bash
nmap -sV -A <ip>
```

### Casey's better nmap scan that I use everytime
```bash
nmap -sC -sV -oN scan.nmap <ip>
```

## Metasploit

### NMAP Scan

```bash
msf 5> db_nmap -sV -A -p 21,22,25,80,110,443,445,8080 <ip>
```

### Standard Port Scan

```bash
msf5
```

```bash
use auxiliary/scanner/portscan/tcp
```

```bash
set RHOSTS <ip>
```

```bash
set PORTS 21,22,25,80,110,443,445,8080
```

```bash
set THREADS 3
```

```bash
run
```

### Searchsploit

```bash
searchspliot <service name and version>
```
