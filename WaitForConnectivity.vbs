' This script is provided as is and should be used just as a sample for waiting for Windows Azure Connect adapter to be connected

' To use this script:
' cscript WaitForConnectivity.vbs

Dim oShell,oExecuteObj,strcmd,bConnected
Set oShell = CreateObject ("Wscript.Shell")
bConnected = False
Do While Not bConnected
    Set oExecuteObj = oShell.Exec("cmd /c netsh interface ipv6 show interfaces interface=""Windows Azure Connect""") 
    Do While Not oExecuteObj.StdOut.AtEndOfStream 
        strcmd = oExecuteObj.StdOut.ReadLine() 
        If Instr(strcmd, ": connected") > 0 Then 
            Wscript.Echo "Windows Azure Connect interface connected"
            bConnected = True 
            Exit Do 
        End If
     Loop
     If Not bConnected Then
        Wscript.Echo "Windows Azure Connect interface disabled, retrying"
        WScript.Sleep(30*1000)
     End If
Loop
