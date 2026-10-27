; Instalador de Windows (Inno Setup 6) para la carpeta de PyInstaller.
; Por usuario y sin permisos de administrador: el programa va a %LOCALAPPDATA%\Programs y los
; enlaces openid4vp:// y openid-credential-offer:// a HKCU, igual que 'oid4vc-wallet install-handler'.
; Los datos del wallet (%APPDATA%\oid4vc-wallet) no se tocan al desinstalar.
; Uso:  iscc /DAppVersion=0.5.1 /DSourceDir=dist\oid4vc-wallet /DOutputDir=dist packaging\oid4vc-wallet.iss

#ifndef AppVersion
  #error Pass /DAppVersion=X.Y.Z
#endif
#ifndef SourceDir
  #define SourceDir "..\dist\oid4vc-wallet"
#endif
#ifndef OutputDir
  #define OutputDir "..\dist"
#endif

[Setup]
; AppId fijo: identifica la aplicación entre versiones (actualizar = instalar encima).
AppId={{6E0B7A52-3C1F-4F0E-9B7D-2D5A8C41E9A3}
AppName=OID4VC Wallet
AppVersion={#AppVersion}
AppPublisher=CitComAI Hub
AppPublisherURL=https://github.com/CitComAI-Hub/oid4vc-wallet
AppSupportURL=https://github.com/CitComAI-Hub/oid4vc-wallet/issues
AppUpdatesURL=https://github.com/CitComAI-Hub/oid4vc-wallet/releases
DefaultDirName={autopf}\OID4VC Wallet
DefaultGroupName=OID4VC Wallet
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=OID4VC_Wallet-{#AppVersion}-windows-x64-setup
SetupIconFile=oid4vc-wallet.ico
UninstallDisplayIcon={app}\oid4vc-wallet-gui.exe
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
Name: "{autoprograms}\OID4VC Wallet"; Filename: "{app}\oid4vc-wallet-gui.exe"
Name: "{autodesktop}\OID4VC Wallet"; Filename: "{app}\oid4vc-wallet-gui.exe"; Tasks: desktopicon

[Registry]
; Mismas claves que desktop._install_windows(); se borran al desinstalar.
Root: HKCU; Subkey: "Software\Classes\openid4vp"; ValueType: string; ValueName: ""; ValueData: "URL:openid4vp"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\openid4vp"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""
Root: HKCU; Subkey: "Software\Classes\openid4vp\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\oid4vc-wallet-gui.exe"" ""%1"""
Root: HKCU; Subkey: "Software\Classes\openid-credential-offer"; ValueType: string; ValueName: ""; ValueData: "URL:openid-credential-offer"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\openid-credential-offer"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""
Root: HKCU; Subkey: "Software\Classes\openid-credential-offer\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\oid4vc-wallet-gui.exe"" ""%1"""

[Run]
Filename: "{app}\oid4vc-wallet-gui.exe"; Description: "{cm:LaunchProgram,OID4VC Wallet}"; Flags: nowait postinstall skipifsilent
