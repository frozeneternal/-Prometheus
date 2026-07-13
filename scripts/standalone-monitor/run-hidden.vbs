Option Explicit

Function QuoteArg(value)
  QuoteArg = """" & Replace(CStr(value), """", "\""") & """"
End Function

Dim shell
Dim command
Dim i

If WScript.Arguments.Count = 0 Then
  WScript.Quit 2
End If

command = ""
For i = 0 To WScript.Arguments.Count - 1
  If Len(command) > 0 Then
    command = command & " "
  End If
  command = command & QuoteArg(WScript.Arguments(i))
Next

Set shell = CreateObject("WScript.Shell")
WScript.Quit shell.Run(command, 0, True)
