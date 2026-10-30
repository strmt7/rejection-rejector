; Rejection Rejector — component-selectable Windows installer (Inno Setup 6)
;
; Two installable components, both selected by default; the wizard refuses
; to continue when none is selected. The product surface is the command-line
; toolchain and the local web console (rr web): there is no desktop
; application UI. Every path is a build input: the build system passes
; /AppVersion and /SourceDir; nothing is machine-specific.

#define AppName "Rejection Rejector"
#ifndef AppVersion
  #define AppVersion "0.2.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\target\release"
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
Name: "cli"; Description: "Command-line tools (rr.exe, including rr tui)"; Types: custom
Name: "web"; Description: "Local web console (served by rr web on the loopback address)"; Types: custom

[Tasks]
Name: "webicon"; Description: "Create a Start-menu shortcut for the local web console"; Components: web

[Files]
Source: "{#SourceDir}\rr.exe"; DestDir: "{app}"; Components: cli
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Local web console"; Filename: "{app}\rr.exe"; Parameters: "web"; Components: web
Name: "{autodesktop}\Local web console"; Filename: "{app}\rr.exe"; Parameters: "web"; Components: web; Tasks: webicon
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
    if not (WizardIsComponentSelected('cli') or WizardIsComponentSelected('web')) then
    begin
      MsgBox('Select at least one component (Command-line tools or Local web console).', mbError, MB_OK);
      Result := False;
    end;
  end;
end;
