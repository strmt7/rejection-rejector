; Rejection Rejector — component-selectable Windows installer (Inno Setup 6)
;
; Three installable components, all selected by default; the wizard refuses
; to continue when none is selected. Every path is a build input: the build
; system passes /AppVersion and /SourceDir; nothing is machine-specific.

#define AppName "Rejection Rejector"
#ifndef AppVersion
  #define AppVersion "0.2.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\\target\\release"
#endif

[Setup]
AppId={{7F1E2C94-5A6B-4C3D-9E8F-1A2B3C4D5E6F}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Rejection Rejector contributors
DefaultDirName={autopf}\RejectionRejector
DefaultGroupName={#AppName}
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64
OutputBaseFilename=rejection-rejector-setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Per-user installation preserves least privilege; no machine-wide changes.

[Types]
Name: "custom"; Description: "Custom installation"; Flags: iscustom

[Components]
Name: "desktop"; Description: "Desktop application (rejection-rejector.exe)"; Types: custom
Name: "cli"; Description: "Command-line tools (rr.exe, including rr tui and rr web)"; Types: custom
Name: "web"; Description: "Local web interface (served by rr web on the loopback address)"; Types: custom

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut for the application"; Components: desktop
Name: "webicon"; Description: "Create a Start-menu shortcut for the local web interface"; Components: web

[Files]
Source: "{#SourceDir}\rejection-rejector.exe"; DestDir: "{app}"; Components: desktop
Source: "{#SourceDir}\rr.exe"; DestDir: "{app}"; Components: cli
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\rejection-rejector.exe"; Components: desktop
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\rejection-rejector.exe"; Components: desktop; Tasks: desktopicon
Name: "{group}\Local web interface"; Filename: "{app}\rr.exe"; Parameters: "web"; Components: web
Name: "{autodesktop}\Local web interface"; Filename: "{app}\rr.exe"; Parameters: "web"; Components: web; Tasks: webicon
Name: "{group}\Command-line tools"; Filename: "{app}\rr.exe"; Components: cli

[Run]
; Nothing is launched at install time; the least-privilege posture holds.

[Code]
// At least one component must be selected: the installer refuses to proceed
// with an empty selection before any file is written.
function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = wpSelectComponents then
  begin
    if not (WizardIsComponentSelected('desktop') or WizardIsComponentSelected('cli')
        or WizardIsComponentSelected('web')) then
    begin
      MsgBox('Select at least one component (Desktop, Command-line tools, or Local web interface).', mbError, MB_OK);
      Result := False;
    end;
  end;
end;
