@echo off
:: version #
set Version=1.0 beta

:: Getting Admin Permissions https://stackoverflow.com/questions/1894967/how-to-request-administrator-access-inside-a-batch-file
echo Checking for Administrative Privelages...
timeout /t 3 /nobreak > NUL
IF "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) ELSE (
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)

if '%errorlevel%' NEQ '0' (
    goto UACPrompt
) else ( goto GotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params= %*
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %params:"=""%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:GotAdmin
    pushd "%CD%"
    CD /D "%~dp0"

:: Home main
:Main
chcp 65001 >nul 2>&1
cls
set c=[33m
set t=[0m
set w=[95m
set y=[0m
set u=[4m
set q=[0m
echo.
echo.
echo.
echo.
echo.  %c%╔═══╗╔══╗╔══╗╔════╗───╔══╗╔╗─╔╗╔══╗╔════╗╔══╗╔╗──╔╗──%c%
echo.  %c%║╔═╗║║╔╗║║╔═╝╚═╗╔═╝───╚╗╔╝║╚═╝║║╔═╝╚═╗╔═╝║╔╗║║║──║║──%c%
echo.  %c%║╚═╝║║║║║║╚═╗──║║──────║║─║╔╗─║║╚═╗──║║──║╚╝║║║──║║──%c%
echo.  %c%║╔══╝║║║║╚═╗║──║║──────║║─║║╚╗║╚═╗║──║║──║╔╗║║║──║║──%c%
echo.  %c%║║───║╚╝║╔═╝║──║║─────╔╝╚╗║║─║║╔═╝║──║║──║║║║║╚═╗║╚═╗%c%
echo.  %c%╚╝───╚══╝╚══╝──╚╝─────╚══╝╚╝─╚╝╚══╝──╚╝──╚╝╚╝╚══╝╚══╝%c%
echo.
echo.
echo.            %t%Windows%t%             
echo.  %w%══════════════════════%y%
echo.  %c%[%y% %c%%u%1%q%%t% %w%]%y% %c%PowerPlanV1 Change PowerPlanV2%t%
echo.  %c%[%y% %c%%u%2%q% %t%%w%]%y% %c%Services%t%
echo.  %c%[%y% %c%%u%3%q%%t% %w%]%y% %c%Network%t%
echo.  %c%[%y% %c%%u%4%q% %t%%w%]%y% %c%Game Priority%t%
echo.  %c%[%y% %c%%u%5%q% %t%%w%]%y% %c%Clear temp%t%
echo.  %c%[%y% %c%%u%6%q% %t%%w%]%y% %c%SettingsV2 (recommend)%t%
echo
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto powerplan
if '%choice%'=='2' goto services
if '%choice%'=='3' goto network
if '%choice%'=='4' goto games
if '%choice%'=='5' goto clear
if '%choice%'=='6' goto setV2

:: number 1 menu
:powerplan
cls
echo PowerPlanV2
echo.

:: Import power plan
@REM Import power plan for all users
curl -g -k -L -# -o "C:\powerplan.pow" "https://cdn.discordapp.com/attachments/1225846086111854706/1228754893968248852/powerplan.pow?ex=662d322b&is=661abd2b&hm=2f136b2e41366de65cf47742bbb6f3d62aa447c710ec8a9ad60e72aa00ea64e1&"
powercfg -import "C:\powerplan.pow" 120ea5af-085f-41e2-8e8b-dd538b38e4f7
powercfg -setactive 120ea5af-085f-41e2-8e8b-dd538b38e4f7
timeout /t 3 /nobreak > NUL
goto main

:: number 2 menu
:services
cls

Powershell Set-Service AppVClient -StartupType Disabled
Powershell Set-Service NetTcpPortSharing -StartupType Disabled
Powershell Set-Service CscService -StartupType Disabled
Powershell Set-Service PhoneSvc -StartupType Disabled
Powershell Set-Service Spooler -StartupType Disabled
Powershell Set-Service PrintNotify -StartupType Disabled
Powershell Set-Service QWAVE -StartupType Disabled
Powershell Set-Service RmSvc -StartupType Disabled
Powershell Set-Service RemoteAccess -StartupType Disabled
Powershell Set-Service SensorDataService -StartupType Disabled
Powershell Set-Service SensrSvc -StartupType Disabled
Powershell Set-Service SensorService -StartupType Disabled
Powershell Set-Service ShellHWDetection -StartupType Disabled
Powershell Set-Service SCardSvr -StartupType Disabled
Powershell Set-Service ScDeviceEnum -StartupType Disabled
Powershell Set-Service SSDPSRV -StartupType Disabled
Powershell Set-Service WiaRpc -StartupType Disabled
Powershell Set-Service upnphost -StartupType Disabled
Powershell Set-Service UserDataSvc -StartupType Disabled
Powershell Set-Service UevAgentService -StartupType Disabled
Powershell Set-Service WalletService -StartupType Disabled
Powershell Set-Service FrameServer -StartupType Disabled
Powershell Set-Service stisvc -StartupType Disabled
Powershell Set-Service wisvc -StartupType Disabled
Powershell Set-Service icssvc -StartupType Disabled
Powershell Set-Service WSearch -StartupType Disabled
Powershell Set-Service XblAuthManager -StartupType Disabled
Powershell Set-Service XblGameSave -StartupType Disabled
Powershell Set-Service SEMgrSvc -StartupType Disabled
Powershell Set-Service SysMain -StartupType Disabled
Powershell Set-Service diagnosticshub.standardcollector.service -StartupType Disabled
Powershell Set-Service diagsvc -StartupType Disabled
Powershell Set-Service WbioSrvc -StartupType Disabled
Powershell Set-Service MapsBloker -StartupType Disabled
Powershell Set-Service lfsvc -StartupType Disabled
Powershell Set-Service UevAgentService -StartupType Disabled
Powershell Set-Service WinDefend -StartupType Disabled
Powershell Set-Service SecurityHealthService -StartupType Disabled
Powershell Set-Service WdNisSvc -StartupType Disabled
Powershell Set-Service Sense -StartupType Disabled
Powershell Set-Service wscsvc -StartupType Disabled
Powershell Set-Service AxInstSV -StartupType Disabled
Powershell Set-Service dmwappushservice -StartupType Disabled
Powershell Set-Service SharedAccess -StartupType Disabled
Powershell Set-Service lltdsvc -StartupType Disabled
sc delete DiagTrack
sc delete dmwappushservice
timeout /t 3 /nobreak > NUL
goto main

:: number 3 menu
:network
cls

echo Configuring Sock Address Size
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MinSockAddrLength" /t REG_DWORD /d "16" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MaxSockAddrLength" /t REG_DWORD /d "16" /f
timeout /t 1 /nobreak > NUL

:: Disable Nagle's Algorithm
echo Disabling Nagle's Algorithm
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
timeout /t 1 /nobreak > NUL

:: Disable Delivery Optimization
echo Disabling Delivery Optimization
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f
timeout /t 1 /nobreak > NUL

:: Limit Number of SMB Sessions
echo Limiting SMB Sessions
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
timeout /t 1 /nobreak > NUL

:: Disable Oplocks
echo Disabling Oplocks
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f
timeout /t 1 /nobreak > NUL

:: Set IRP Stack Size
echo Setting IRP Stack Size
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "20" /f
timeout /t 1 /nobreak > NUL

:: Disable Sharing Violations
echo Disabling Sharing Violations
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f
timeout /t 1 /nobreak > NUL

:: Get the Sub ID of the Network Adapter
for /f %%n in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}" /v "*SpeedDuplex" /s ^| findstr  "HKEY"') do (

:: Disable NIC Power Savings
echo Disabling NIC Power Savings
reg add "%%n" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f 
reg add "%%n" /v "AutoDisableGigabit" /t REG_SZ /d "0" /f 
reg add "%%n" /v "AdvancedEEE" /t REG_SZ /d "0" /f 
reg add "%%n" /v "DisableDelayedPowerUp" /t REG_SZ /d "2" /f 
reg add "%%n" /v "*EEE" /t REG_SZ /d "0" /f 
reg add "%%n" /v "EEE" /t REG_SZ /d "0" /f 
reg add "%%n" /v "EnablePME" /t REG_SZ /d "0" /f
reg add "%%n" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f 
reg add "%%n" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f 
reg add "%%n" /v "EnableSavePowerNow" /t REG_SZ /d "0" /f 
reg add "%%n" /v "EnablePowerManagement" /t REG_SZ /d "0" /f
reg add "%%n" /v "EnableDynamicPowerGating" /t REG_SZ /d "0" /f
reg add "%%n" /v "EnableConnectedPowerGating" /t REG_SZ /d "0" /f
reg add "%%n" /v "EnableWakeOnLan" /t REG_SZ /d "0" /f 
reg add "%%n" /v "GigaLite" /t REG_SZ /d "0" /f
reg add "%%n" /v "NicAutoPowerSaver" /t REG_SZ /d "2" /f 
reg add "%%n" /v "PowerDownPll" /t REG_SZ /d "0" /f
reg add "%%n" /v "PowerSavingMode" /t REG_SZ /d "0" /f 
reg add "%%n" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f 
reg add "%%n" /v "SmartPowerDownEnable" /t REG_SZ /d "0" /f 
reg add "%%n" /v "S5NicKeepOverrideMacAddrV2" /t REG_SZ /d "0" /f
reg add "%%n" /v "S5WakeOnLan" /t REG_SZ /d "0" /f 
reg add "%%n" /v "ULPMode" /t REG_SZ /d "0" /f 
reg add "%%n" /v "WakeOnDisconnect" /t REG_SZ /d "0" /f
reg add "%%n" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f
reg add "%%n" /v "*WakeOnPattern" /t REG_SZ /d "0" /f
reg add "%%n" /v "WakeOnLink" /t REG_SZ /d "0" /f 
reg add "%%n" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f
timeout /t 1 /nobreak > NUL

:: Disable Jumbo Frame
echo Disabling Jumbo Frame
reg add "%%n" /v "JumboPacket" /t REG_SZ /d "1514" /f
timeout /t 1 /nobreak > NUL

:: Configure Receive/Transmit Buffers
echo Configuring Buffer Sizes
reg add "%%n" /v "TransmitBuffers" /t REG_SZ /d "4096" /f
reg add "%%n" /v "ReceiveBuffers" /t REG_SZ /d "512" /f
timeout /t 1 /nobreak > NUL

:: Configure Offloads
echo Configuring Offloads
reg add "%%n" /v "IPChecksumOffloadIPv4" /t REG_SZ /d "0" /f 
reg add "%%n" /v "LsoV1IPv4" /t REG_SZ /d "0" /f 
reg add "%%n" /v "LsoV2IPv4" /t REG_SZ /d "0" /f 
reg add "%%n" /v "LsoV2IPv6" /t REG_SZ /d "0" /f 
reg add "%%n" /v "PMARPOffload" /t REG_SZ /d "0" /f
reg add "%%n" /v "PMNSOffload" /t REG_SZ /d "0" /f 
reg add "%%n" /v "TCPChecksumOffloadIPv4" /t REG_SZ /d "0" /f 
reg add "%%n" /v "TCPChecksumOffloadIPv6" /t REG_SZ /d "0" /f 
reg add "%%n" /v "UDPChecksumOffloadIPv6" /t REG_SZ /d "0" /f 
reg add "%%n" /v "UDPChecksumOffloadIPv4" /t REG_SZ /d "0" /f 
timeout /t 1 /nobreak > NUL

:: Enable RSS in NIC
echo Enabling RSS in NIC
reg add "%%n" /v "RSS" /t REG_SZ /d "1" /f
reg add "%%n" /v "*NumRssQueues" /t REG_SZ /d "2" /f
reg add "%%n" /v "RSSProfile" /t REG_SZ /d "3" /f
timeout /t 1 /nobreak > NUL

:: Disable Flow Control
echo Disabling Flow Control
reg add "%%n" /v "*FlowControl" /t REG_SZ /d "0" /f
reg add "%%n" /v "FlowControlCap" /t REG_SZ /d "0" /f
timeout /t 1 /nobreak > NUL

:: Remove Interrupt Delays
echo Removing Interrupt Delays
reg add "%%n" /v "TxIntDelay" /t REG_SZ /d "0" /f 
reg add "%%n" /v "TxAbsIntDelay" /t REG_SZ /d "0" /f 
reg add "%%n" /v "RxIntDelay" /t REG_SZ /d "0" /f 
reg add "%%n" /v "RxAbsIntDelay" /t REG_SZ /d "0" /f
timeout /t 1 /nobreak > NUL

:: Remove Adapter Notification
echo Removing Adapter Notification Sending
reg add "%%n" /v "FatChannelIntolerant" /t REG_SZ /d "0" /f
timeout /t 1 /nobreak > NUL

:: Disable Interrupt Moderation
echo Disabling Interrupt Moderation
reg add "%%n" /v "*InterruptModeration" /t REG_SZ /d "0" /f
timeout /t 1 /nobreak > NUL
)

:: Enable WeakHost Send and Recieve
echo Enabling WH Send and Recieve
powershell "Get-NetAdapter -IncludeHidden | Set-NetIPInterface -WeakHostSend Enabled -WeakHostReceive Enabled -ErrorAction SilentlyContinue"
timeout /t 1 /nobreak > NUL

:: Disable NetBIOS
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v "NetbiosOptions" /t REG_DWORD /d "2" /f
echo let's return home..
timeout /t 3 /nobreak > NUL
goto main

:: number 4 menu
:games
set z=[7m
set i=[1m
set q=[0m
echo %z%Are you on cs2, valorant fortnite?%q%
echo.
echo %i%cs2 = 1%q%
echo.
echo %i%valorant = 2%q%
echo.
echo %i%fortnite = 3%q%
echo.
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto cs2
if '%choice%'=='2' goto valorant
if '%choice%'=='3' goto fortnite

:cs2
cls
title priority cs2..
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "8" /f
echo Wait 2 second...
timeout /t 2 /nobreak >nul
cls
echo Wait 1 second...
timeout /t 1 /nobreak >nul
goto home

:valorant
cls
title priority valorant..
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\VALORANT.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "8" /f
echo Wait 2 second...
timeout /t 2 /nobreak >nul
cls
echo Wait 1 second...
timeout /t 1 /nobreak >nul
goto home

:fortnite
cls
title priority fortnite..
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe" /v "CpuPriorityClass" /t REG_DWORD /d "8" /f
echo Wait 2 second...
timeout /t 2 /nobreak >nul
cls
echo Wait 1 second...
timeout /t 1 /nobreak >nul
goto main

:: number 5 menu
:clear
cls
@REM Cleaning PC
del /s /f /q c:\windows\temp.
del /s /f /q C:\WINDOWS\Prefetch
del /s /f /q %temp%.
del /s /f /q %systemdrive%\*.tmp
del /s /f /q %systemdrive%\*._mp
del /s /f /q %systemdrive%\*.log 
del /s /f /q %systemdrive%\*.gid 
del /s /f /q %systemdrive%\*.chk 
del /s /f /q %systemdrive%\*.old
del /s /f /q %systemdrive%\recycled\*.*
del /s /f /q %systemdrive%\$Recycle.Bin\*.*
del /s /f /q %windir%\*.bak
del /s /f /q %windir%\prefetch\*.*
del /s /f /q %LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db
del /s /f /q %LocalAppData%\Microsoft\Windows\Explorer\*.db 
del /f /q %SystemRoot%\Logs\CBS\CBS.log 
del /f /q %SystemRoot%\Logs\DISM\DISM.log
deltree /y c:\windows\tempor~1 
deltree /y c:\windows\temp 
deltree /y c:\windows\tmp 
deltree /y c:\windows\ff*.tmp 
deltree /y c:\windows\history 
deltree /y c:\windows\cookies 
deltree /y c:\windows\recent 
deltree /y c:\windows\spool\printers
cls
goto main

:: number 6 menu
:setV2
