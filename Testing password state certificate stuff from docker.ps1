Set-PasswordstateComputerName -ComputerName passwordstate.tervis.prv
Set-PasswordstateAPIType -APIType Standard
set-location (Get-UserPSModulePath)
set-location /root/.local/share/powershell/Modules
gci -file -filter *.cer | copy-item -Destination /usr/local/share/ca-certificates/

Set-PSBreakpoint -command invoke-restmethod
Get-PasswordstatePassword -ID 3985