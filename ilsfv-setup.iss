; Script generated by the Inno Setup Script Wizard.
; SEE THE DOCUMENTATION FOR DETAILS ON CREATING INNO SETUP SCRIPT FILES!

[Setup]
; NOTE: The value of AppId uniquely identifies this application.
; Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppId={{D463AB63-D949-4FB1-B586-968FBBE529D2}
AppName=ilSFV
AppVerName=ilSFV 1.0.8
AppPublisher=Jud White
AppPublisherURL=http://www.cdtag.com/ilsfv
AppSupportURL=http://www.cdtag.com/ilsfv
AppUpdatesURL=http://www.cdtag.com/ilsfv
DefaultDirName={pf}\ilSFV
DefaultGroupName=ilSFV
AllowNoIcons=yes
OutputDir=C:\Projects\CDTag\bin-ilSFV\setup\output
OutputBaseFilename=ilSFVsetup
SetupIconFile=C:\Projects\CDTag\ilSFV\ilSFV\MiniDisc Check.ico
Compression=lzma
SolidCompression=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}";

[Files]
Source: "C:\Projects\CDTag\bin-ilSFV\setup\ilSFV.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\Projects\CDTag\bin-ilSFV\setup\cache.sdf"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\Projects\CDTag\bin-ilSFV\setup\settings.sdf"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\Projects\CDTag\bin-ilSFV\setup\sqlceca35.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\Projects\CDTag\bin-ilSFV\setup\sqlcecompact35.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\Projects\CDTag\bin-ilSFV\setup\sqlceer35EN.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\Projects\CDTag\bin-ilSFV\setup\sqlceme35.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\Projects\CDTag\bin-ilSFV\setup\sqlceoledb35.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\Projects\CDTag\bin-ilSFV\setup\sqlceqp35.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\Projects\CDTag\bin-ilSFV\setup\sqlcese35.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\Projects\CDTag\bin-ilSFV\setup\complete_ok.wav"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\Projects\CDTag\bin-ilSFV\setup\complete_error.wav"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\Projects\CDTag\bin-ilSFV\setup\System.Data.SqlServerCe.dll"; DestDir: "{app}"; Flags: ignoreversion
; NOTE: Don't use "Flags: ignoreversion" on any shared system files

[Icons]
Name: "{group}\ilSFV"; Filename: "{app}\ilSFV.exe"
Name: "{group}\{cm:UninstallProgram,ilSFV}"; Filename: "{uninstallexe}"
Name: "{commondesktop}\ilSFV"; Filename: "{app}\ilSFV.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\ilSFV.exe"; Description: "{cm:LaunchProgram,ilSFV}"; Flags: nowait postinstall skipifsilent

