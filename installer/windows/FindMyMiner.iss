#define AppName "Find My Miner"
#define AppVersion "0.0.1"
#define AppPublisher "BitsPleaseYT"

[Setup]
AppId={{A7CB8B9A-41E5-4B97-B451-9235D5C15FE8}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\Find My Miner
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=..\..\artifacts
OutputBaseFilename=Find-My-Miner-Setup-{#AppVersion}-win-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
WizardImageFile=..\installer-splash.png
SetupIconFile=..\..\src\IpScanner.App\Assets\app.ico
UninstallDisplayIcon={app}\FindMyMiner.exe
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest

[Files]
Source: "..\..\publish\win-x64\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\FindMyMiner.exe"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\FindMyMiner.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\FindMyMiner.exe"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

