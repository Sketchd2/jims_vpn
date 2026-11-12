; JimsVPN Windows installer. Build with: makensis -DVERSION=1.2.3 -DSRC=<dir with exes and wintun.dll> -DOUT=<file>
Unicode true
!include "MUI2.nsh"

Name "JimsVPN"
OutFile "${OUT}"
InstallDir "$PROGRAMFILES64\JimsVPN"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
VIProductVersion "0.0.0.0"
VIAddVersionKey "ProductName" "JimsVPN"
VIAddVersionKey "FileDescription" "JimsVPN installer"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" ""

!define UNINST "Software\Microsoft\Windows\CurrentVersion\Uninstall\JimsVPN"

!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetRegView 64
  ; Upgrading: stop what is running so the files can be replaced. Joined networks are kept.
  nsExec::Exec 'taskkill /F /IM jvpn-tray.exe'
  IfFileExists "$INSTDIR\jvpn.exe" 0 +2
    nsExec::Exec '"$INSTDIR\jvpn.exe" service uninstall'

  SetOutPath "$INSTDIR"
  File "${SRC}\jvpn.exe"
  File "${SRC}\jvpn-tray.exe"
  File "${SRC}\wintun.dll"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  nsExec::ExecToLog '"$INSTDIR\jvpn.exe" service install'
  Pop $0
  StrCmp $0 "0" +2
    MessageBox MB_ICONEXCLAMATION "The JimsVPN service could not be started (code $0). See C:\ProgramData\JimsVPN\jvpn.log."

  ; Tray icon for every user at sign-in.
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "JimsVPN" '"$INSTDIR\jvpn-tray.exe"'
  CreateShortcut "$SMPROGRAMS\JimsVPN.lnk" "$INSTDIR\jvpn-tray.exe"

  WriteRegStr HKLM "${UNINST}" "DisplayName" "JimsVPN"
  WriteRegStr HKLM "${UNINST}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINST}" "Publisher" "JimsVPN"
  WriteRegStr HKLM "${UNINST}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINST}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINST}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST}" "NoRepair" 1

  ; Start the tray as the signed-in user rather than elevated.
  Exec '"$WINDIR\explorer.exe" "$INSTDIR\jvpn-tray.exe"'
SectionEnd

Section "Uninstall"
  SetRegView 64
  nsExec::Exec 'taskkill /F /IM jvpn-tray.exe'
  nsExec::Exec '"$INSTDIR\jvpn.exe" service uninstall'
  Sleep 1000
  Delete "$INSTDIR\jvpn.exe"
  Delete "$INSTDIR\jvpn-tray.exe"
  Delete "$INSTDIR\wintun.dll"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\JimsVPN.lnk"
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "JimsVPN"
  DeleteRegKey HKLM "${UNINST}"
  ; C:\ProgramData\JimsVPN (network memberships and keys) is left in place on purpose.
SectionEnd
