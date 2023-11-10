## Connect to SSH
```bash
ssh username@<target-ip>
```
```bash
ssh username@<target-ip> -p 22
```

### Download a file
```bash
scp user@<ip>:/home/<user>/path/to/file.txt .
```

### With Private Key
```bash
ssh -i id_rsa username@<target-ip>
```

## Connect Windows with AD
```bash
ssh domain-name\\username@domain-controller
```
