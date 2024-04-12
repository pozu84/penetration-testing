Testing Macro open Powershell.exe

Sub AutoOpen()
  MyMacro
End Sub

Sub Document_Open()
  MyMacro
End Sub

Sub MyMacro()
  CreateObject("Wscript.Shell").Run "powershell"
End Sub