; Windows installer (Inno Setup 6) for the PyInstaller folder.
; Per user and without administrator rights: the program goes to %LOCALAPPDATA%\Programs and the
; openid4vp:// and openid-credential-offer:// links to HKCU, like 'atesta-id-wallet install-handler'.
; The wallet data (%APPDATA%\atesta-id-wallet) is not touched when uninstalling.
; Usage:  iscc /DAppVersion=0.6.0 /DSourceDir=dist\atesta-id-wallet /DOutputDir=dist packaging\atesta-id-wallet.iss

#ifndef AppVersion
  #error Pass /DAppVersion=X.Y.Z
#endif
#ifndef SourceDir
  #define SourceDir "..\dist\atesta-id-wallet"
#endif
#ifndef OutputDir
  #define OutputDir "..\dist"
#endif

[Setup]
; Fixed AppId: identifies the application across versions (updating = installing over it).
AppId={{6E0B7A52-3C1F-4F0E-9B7D-2D5A8C41E9A3}
AppName=Atesta ID Wallet
AppVersion={#AppVersion}
AppPublisher=CitComAI Hub
AppPublisherURL=https://github.com/CitComAI-Hub/atesta-id-wallet
AppSupportURL=https://github.com/CitComAI-Hub/atesta-id-wallet/issues
AppUpdatesURL=https://github.com/CitComAI-Hub/atesta-id-wallet/releases
DefaultDirName={autopf}\Atesta ID Wallet
DefaultGroupName=Atesta ID Wallet
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=Atesta_ID_Wallet-{#AppVersion}-windows-x64-setup
SetupIconFile=atesta-id-wallet.ico
UninstallDisplayIcon={app}\atesta-id-wallet-gui.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "da"; MessagesFile: "compiler:Languages\Danish.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Atesta ID Wallet"; Filename: "{app}\atesta-id-wallet-gui.exe"
Name: "{autodesktop}\Atesta ID Wallet"; Filename: "{app}\atesta-id-wallet-gui.exe"; Tasks: desktopicon

[Registry]
; Same keys as desktop._install_windows(); removed when uninstalling.
Root: HKCU; Subkey: "Software\Classes\openid4vp"; ValueType: string; ValueName: ""; ValueData: "URL:openid4vp"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\openid4vp"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""
Root: HKCU; Subkey: "Software\Classes\openid4vp\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\atesta-id-wallet-gui.exe"" ""%1"""
Root: HKCU; Subkey: "Software\Classes\openid-credential-offer"; ValueType: string; ValueName: ""; ValueData: "URL:openid-credential-offer"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\openid-credential-offer"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""
Root: HKCU; Subkey: "Software\Classes\openid-credential-offer\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\atesta-id-wallet-gui.exe"" ""%1"""

[Run]
Filename: "{app}\atesta-id-wallet-gui.exe"; Description: "{cm:LaunchProgram,Atesta ID Wallet}"; Flags: nowait postinstall skipifsilent
