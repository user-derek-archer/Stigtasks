# =============== PREP ===============
New-Item -ItemType Directory -Force -Path "C:\Logs" | Out-Null

# 1. Disable USB Storage (WN12-CC-000106)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4 -Force
Add-Content -Path "C:\Logs\stig_usb_block.log" -Value "[$(Get-Date)] USB storage disabled."

# 2. Enable Audit Policy for Logon/Logoff (WN12-AU-000001)
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
Add-Content -Path "C:\Logs\stig_auditpolicy.log" -Value "[$(Get-Date)] Logon/Logoff auditing enabled."

# 3. Enforce Password Complexity (WN12-AC-000201)
$secpol = "C:\Temp\secpol.cfg"
New-Item -ItemType Directory -Force -Path "C:\Temp" | Out-Null
secedit /export /cfg $secpol
(Get-Content $secpol) -replace 'PasswordComplexity = \d', 'PasswordComplexity = 1' | Set-Content $secpol
secedit /configure /db secedit.sdb /cfg $secpol /areas SECURITYPOLICY
Add-Content -Path "C:\Logs\stig_pwdcomplexity.log" -Value "[$(Get-Date)] Password complexity enforced."

# 4. Restrict Anonymous SID Enumeration (WN12-SO-000034)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Force
Add-Content -Path "C:\Logs\stig_anonymous_restrict.log" -Value "[$(Get-Date)] Anonymous SID enumeration restricted."

# 5. Configure Log Size Minimum (WN12-AU-000051)
wevtutil sl Security /ms:196608
Add-Content -Path "C:\Logs\stig_logsize.log" -Value "[$(Get-Date)] Security log size set to 192MB."

# 6. Disable SMBv1 (WN12-00-000040)
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
Add-Content -Path "C:\Logs\stig_smbv1_disable.log" -Value "[$(Get-Date)] SMBv1 disabled."

# 7. Enforce Lock Screen After 15 Minutes (WN12-AC-000501)
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeout" -Value "900"
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Value "1"
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Value "1"
Add-Content -Path "C:\Logs\stig_lockscreen.log" -Value "[$(Get-Date)] Lock screen timeout configured."

# 8. Start Windows Defender if Not Running (WN12-AV-000100)
$defender = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
if ($defender.Status -ne 'Running') {
    Start-Service WinDefend
    Add-Content -Path "C:\Logs\stig_defender.log" -Value "[$(Get-Date)] Windows Defender started."
} else {
    Add-Content -Path "C:\Logs\stig_defender.log" -Value "[$(Get-Date)] Windows Defender already running."
}

# Cleanup
Remove-Item -Path "C:\Temp\secpol.cfg" -Force -ErrorAction SilentlyContinue
