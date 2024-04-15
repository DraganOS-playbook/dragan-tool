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
echo.   ████──████─████─████─████─█──█────███─████─████─█──
echo.   █──██─█──█─█──█─█────█──█─██─█─────█──█──█─█──█─█──
echo.   █──██─████─████─█─██─████─█─██─────█──█──█─█──█─█──
echo.   █──██─█─█──█──█─█──█─█──█─█──█─────█──█──█─█──█─█──
echo.   ████──█─█──█──█─████─█──█─█──█─────█──████─████─███
echo.
echo.
echo.            %t%Windows%t%             
echo.  %w%══════════════════════%y%    %w%══════════════════════════════════════════════════════════════%y%
echo.  %c%[%y% %c%%u%1%q%%t% %w%]%y% %c%PowerPlanV1 Change PowerPlanV2%t%
echo.  %c%[%y% %c%%u%2%q% %t%%w%]%y% %c%Services%t%
echo.  %c%[%y% %c%%u%3%q%%t% %w%]%y% %c%Network%t%
echo.  %c%[%y% %c%%u%4%q% %t%%w%]%y% %c%Game Priority%t%
echo.  %c%[%y% %c%%u%5%q% %t%%w%]%y% %c%Clear temp%t%  
echo
set choice=
set /p choice=
set HomeSelection=%errorlevel%
if %HomeSelection% == 1 (call :powerplan)
if %HomeSelection% == 2 (call :services)
if %HomeSelection% == 3 (call :network)
if %HomeSelection% == 4 (call :gamepriority)
if %HomeSelection% == 5 (call :clear)
pause

:PowerPlan
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

:services

..



:: clear pc
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
