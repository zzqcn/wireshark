@ECHO off

REM Batch script for compiling Wireshark on Windows.
REM I have disabled the Qt version build because it's meaningful
REM in 1.99.x i think.

SET PATH=%PATH%:.
SET CYGWIN_BIN=C:\cygwin64\bin
REM SET QT5_BASE_DIR=D:\dev\qt-everywhere-opensource-src-5.3.2\qtbase
REM SET QT5_BIN=D:\dev\qt-everywhere-opensource-src-5.3.2\qtbase\bin
REM SET PATH=%PATH%;%CYGWIN_BIN%;%QT5_BIN%
SET PATH=%PATH%;%CYGWIN_BIN%
SET WIRESHARK_LIB_DIR=D:\dev\Wireshark-win64-libs-1.12

SET VISUALSTUDIOVERSION=10.0
SET PLATFORM=X64
SET WIRESHARK_VERSION_EXTRA=-zzq-x64
SET SNIPER=1
SET DPI=1

ECHO setup Visual Studio environment...
CALL "C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\vcvarsall.bat" amd64

title Command Prompt (MSVC++ 2010 64bit)

REM wireshark库下载地址
REM http://anonsvn.wireshark.org/wireshark-$WIRESHARK_TARGET_PLATFORM-libs/tags/$DOWNLOAD_TAG/packages/

GOTO :eof
