@echo off
echo === CAPE VM Setup Starting ===

echo Disabling Windows Defender...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiVirus /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f
sc config WinDefend start= disabled
sc stop WinDefend

echo Disabling Firewall...
netsh advfirewall set allprofiles state off

echo Disabling Windows Update...
sc config wuauserv start= disabled
sc stop wuauserv
sc config UsoSvc start= disabled
sc stop UsoSvc

echo Disabling UAC...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f

echo Disabling SmartScreen...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f

echo Setting power plan to High Performance...
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg /change monitor-timeout-ac 0
powercfg /change standby-timeout-ac 0

echo Creating user cape...
net user cape cape /add
net localgroup Administrators cape /add

echo Setting auto-logon for cape user...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d cape /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d cape /f

echo Downloading Python 3.10...
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.10.11/python-3.10.11-amd64.exe' -OutFile 'C:\python_installer.exe' -UseBasicParsing"
echo Installing Python silently...
C:\python_installer.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
timeout /t 60 /nobreak
del C:\python_installer.exe

echo Creating CAPE agent directory...
mkdir C:\cape_agent

echo Setting up agent autorun...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v CapeAgent /t REG_SZ /d "python.exe C:\cape_agent\agent.py" /f

echo === CAPE VM Setup Complete ===
echo Machine will reboot in 30 seconds...
shutdown /r /t 30
