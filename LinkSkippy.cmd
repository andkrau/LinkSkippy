@echo off
title Requesting admin rights...
net session >nul 2>&1 || (PowerShell -command "Start-Process '%~nx0' %1 -Verb runas" &exit /b)
title LinkSkippy
color 1f
if "%1" EQU "" set MODE=CDP
if "%1" NEQ "" set MODE=%1

:begin
cls
echo.
echo  #                        #####                              
echo  #       # #    # #    # #     # #    # # #####  #####  #   #
echo  #       # ##   # #   #  #       #   #  # #    # #    #  # # 
echo  #       # # #  # ####    #####  ####   # #    # #    #   #  
echo  #       # #  # # #  #         # #  #   # #####  #####    #  
echo  #       # #   ## #   #  #     # #   #  # #      #        #  
echo  ####### # #    # #    #  #####  #    # # #      #        #  
echo.
if /i "%MODE%" NEQ "CDP" if /i "%MODE%" NEQ "LLDP" goto :unsupported
echo  Configuring packet capture session...
set ETL=%TEMP%\CDP.etl
set TXT=%TEMP%\CDP.txt
call :resetSession
call :sleep 1
call :startSession
echo  Waiting for %MODE% packet...

:checkCounter
for /f "tokens=* delims=" %%a IN ('pktmon counters') do set result=%%a
if "%result%" NEQ "All counters are zero." goto receivedPacket
call :sleep 1
goto checkCounter

:sleep
set /a SECONDS=%1+1
ping -n %SECONDS% 127.0.0.1>nul
goto :eof

:unsupported
echo  Protocol unsupported!
pause>nul
exit

:startSession
PowerShell Invoke-Command {^
  New-NetEventSession -Name 'CDP' -CaptureMode RealtimeLocal -ErrorAction Stop;^
  Add-NetEventPacketCaptureProvider -SessionName 'CDP' -Level 0x0 -LinkLayerAddress 'FF-FF-FF-FF-FF-FF' -CaptureType Physical -TruncationLength 1;^
}>nul 2>&1
call :forEachInterface enterPromiscuous
PowerShell Invoke-Command {^
  Start-NetEventSession -Name 'CDP';^
}>nul 2>&1
IF /I %MODE% EQU CDP pktmon filter add "CDP" -m 01-00-0C-CC-CC-CC -d 0x2000>nul 2>&1
IF /I %MODE% EQU LLDP pktmon filter add "LLDP" -d LLDP>nul 2>&1
pktmon start --capture --type flow --pkt-size 0 --file-name "%ETL%" --comp nics>nul 2>&1
goto :EOF

:resetSession
del /q /s "%ETL%">nul 2>&1
del /q /s "%TXT%">nul 2>&1
pktmon stop>nul 2>&1
pktmon filter remove>nul 2>&1
PowerShell Invoke-Command {^
  Stop-NetEventSession -Name 'CDP';^
}>nul 2>&1
call :forEachInterface exitPromiscuous
PowerShell Invoke-Command {^
  Remove-NetEventPacketCaptureProvider -SessionName 'CDP';^
  Remove-NetEventSession -Name 'CDP';^
}>nul 2>&1
goto :EOF

:forEachInterface
for /f "skip=3 tokens=1-3*" %%a in ('netsh interface show interface') do call :%1 %%a %%b %%c "%%d"
goto :EOF

:enterPromiscuous
if "%1" NEQ "Enabled" GOTO :EOF
PowerShell Invoke-Command {^
  Add-NetEventNetworkAdapter -Name '%~4' -PromiscuousMode $True;^
}>nul 2>&1
goto :EOF

:exitPromiscuous
if "%1" NEQ "Enabled" GOTO :EOF
PowerShell Invoke-Command {^
  Remove-NetEventNetworkAdapter -Name '%~4';^
}>nul 2>&1
goto :EOF

:receivedPacket
echo  %MODE% packet received...
pktmon stop>nul 2>&1
echo  Parsing packet data...
start /min /wait pktmon etl2txt "%ETL%" --out "%TXT%" --verbose 3
IF /I %MODE% EQU CDP call :parseCDP
IF /I %MODE% EQU LLDP call :parseLLDP
call :resetSession
echo.
echo  Press any key to restart...
pause>nul
goto begin

:parseCDP
find "oui Cisco (0x00000c), pid CDP (0x2000)" "%TXT%" >nul 2>&1
if %errorlevel% EQU 0 (
  echo.
  for /f "skip=2 tokens=1-4* delims=(),:" %%a in ('find "Device-ID (" "%TXT%"') do echo  Device:%%e
  for /f "skip=2 tokens=1-4* delims=(),:" %%a in ('find "Address (" "%TXT%"') do echo  Address:%%e
  for /f "skip=2 tokens=1-4* delims=(),:" %%a in ('find "Port-ID (" "%TXT%"') do echo  Port:%%e
  for /f "skip=2 tokens=1-4* delims=(),:" %%a in ('find "Capability (" "%TXT%"') do echo  Capability:%%e
  for /f "skip=2 tokens=1-4* delims=(),:" %%a in ('find "Platform (" "%TXT%"') do echo  Platform:%%e
  for /f "skip=2 tokens=1-4* delims=(),:" %%a in ('find "VTP Management Domain (" "%TXT%"') do echo  Domain:%%e
  for /f "skip=2 tokens=1-4* delims=(),:" %%a in ('find "Native VLAN ID (" "%TXT%"') do echo  VLAN:%%e
  for /f "skip=2 tokens=1-4* delims=(),:" %%a in ('find "Duplex (" "%TXT%"') do echo  Duplex:%%e
)
goto :eof

:parseLLDP
for /f "skip=2 tokens=1 delims=[]" %%a in ('find /n "ethertype LLDP (0x88cc)" "%TXT%"') do set FIRSTLINE=%%a
set TAB=	
SetLocal EnableDelayedExpansion
if "%FIRSTLINE%" NEQ "" (
  echo.
  for /f "skip=%FIRSTLINE% tokens=* delims=" %%a in ('TYPE "%TXT%"') do (
    set LINE=%%a
    if "!LINE:%TAB%=!" EQU "End TLV (0), length 0" goto lldpEnded
    echo !LINE:%TAB%= !
  )
)
:lldpEnded
endlocal
goto :eof
