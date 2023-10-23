## Port 21 (FTP)

### Check for FTP anonymous login

```bash
nmap --script ftp anon
```

### Launch a brute-force attack against FTP servers

```bash
nmap --script ftp-brute
```

### Check if server allows port scanning using FTP bounce method

```bash
nmap --script ftp-bounce
```

### Check for the presence of vsFTPD 2.3.4 backdoor \(CVE-2011-2523\)

```bash
nmap --script ftp-vsftpd-backdoor
```

### Spider the web to find HTTP and/or form based authentication requiring pages

```bash
nmap --script http-auth-finder
```

### Test the server for Cross-Origin-Resource-Sharing

```bash
nmap --script http-cors
```

### Test the server for CSRF vulnerabilities

```bash
nmap --script http-csrf
```

### Test for default credentials used by multiple web applications

```bash
nmap --script http-default-accounts
```

### Test for DOM-based XSS vulnerabilities

```bash
nmap --script http-dombased-xss
```
