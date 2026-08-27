@echo off
setlocal
echo Installing build dependencies...
py -m pip install -r requirements.txt
py -m pip install pyinstaller
echo Building EtherChat.exe...
py -m PyInstaller --noconfirm --clean --onefile --windowed --name EtherChat etherchat.py
echo.
echo DONE. The executable is:
echo dist\EtherChat.exe
pause
