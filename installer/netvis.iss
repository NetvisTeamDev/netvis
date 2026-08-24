; netvis installer - Inno Setup script.
;
; Build it with:
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\netvis.iss
;
; Produces installer\output\netvis-setup.exe, which is the single file you
; publish. Everything the app needs is inside it.

#define AppName    "netvis"
; The version is passed in by build_installer.bat, read straight from
; src\version.h, so the installer and the exe can never disagree (a mismatch is
; what makes auto-update loop forever). The literal below is only a fallback for
; building the .iss by hand.
#ifndef AppVersion
  #define AppVersion "1.0.1"
#endif
#define Publisher  "netvis"
#define AppURL     "https://netvis.cc"
#define ExeName    "netvis.exe"

[Setup]
; A fixed GUID identifies this application to Windows across versions -
; it's how an upgrade replaces the previous install instead of sitting
; beside it in Add/Remove Programs. Never change it.
AppId={{7B2F5C31-9E4A-4C88-B1D6-3A0E5F2D9C47}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#Publisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=output
OutputBaseFilename=netvis-setup
SetupIconFile=..\netvis.ico
UninstallDisplayIcon={app}\{#ExeName}
UninstallDisplayName={#AppName}
AppCopyright=netvis
; Real version metadata on the installer. Windows shows it in Properties,
; and an executable with no version information at all is one more thing
; that makes SmartScreen and antivirus engines suspicious.
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#Publisher}
VersionInfoDescription={#AppName} setup
VersionInfoProductName={#AppName}
; Terms shown before install. A paid product needs them, and Windows users
; expect the page - its absence reads as amateur.
LicenseFile=EULA.txt

; Wizard branding, generated from netvis.ico.
WizardSmallImageFile=wizard-small.bmp
WizardImageFile=wizard-large.bmp

; Stops a second copy of Setup running while the first is mid-install.
SetupMutex=netvis_setup_mutex

Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern

; netvis intercepts traffic through a kernel driver, so it can only run
; elevated - and its files live in Program Files. Asking for admin here
; means the install fails early and clearly rather than half-working.
PrivilegesRequired=admin

; WinDivert is 64-bit only, so refuse 32-bit Windows up front instead of
; installing something that can't start.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "..\netvis.exe";       DestDir: "{app}"; Flags: ignoreversion
; WinDivert is what lets netvis see and filter packets. Both files must sit
; next to the exe - the DLL loads the driver from its own folder.
Source: "..\WinDivert.dll";    DestDir: "{app}"; Flags: ignoreversion
Source: "..\WinDivert64.sys";  DestDir: "{app}"; Flags: ignoreversion
Source: "..\blocklist.txt";    DestDir: "{app}"; Flags: ignoreversion
Source: "..\netvis.ico";       DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}";        Filename: "{app}\{#ExeName}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}";  Filename: "{app}\{#ExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#ExeName}"; Description: "Start {#AppName} now"; \
    Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallRun]
; The scheduled task that starts netvis at logon isn't a file, so removing
; the folder wouldn't remove it - Windows would keep trying to launch a
; program that no longer exists.
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /TN ""netvis"" /F"; \
    Flags: runhidden; RunOnceId: "DelStartupTask"

; WinDivert registers a kernel driver service the first time netvis opens a
; handle. Deleting the program folder does not unregister it, so without
; this an uninstall leaves a kernel service behind - which looks exactly
; like the leftovers people complain about, and is the sort of thing
; security software flags later.
Filename: "{sys}\sc.exe"; Parameters: "stop WinDivert"; \
    Flags: runhidden; RunOnceId: "StopWinDivert"
Filename: "{sys}\sc.exe"; Parameters: "delete WinDivert"; \
    Flags: runhidden; RunOnceId: "DelWinDivert"

; netvis bans IPs with Windows Firewall rules named "netvis-ban-*". These
; live in the firewall, not the program folder, so they must be deleted here
; or an uninstalled netvis would keep blocking those addresses forever.
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""netvis-ban-out-v4"""; \
    Flags: runhidden; RunOnceId: "DelBanOut4"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""netvis-ban-in-v4"""; \
    Flags: runhidden; RunOnceId: "DelBanIn4"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""netvis-ban-out-v6"""; \
    Flags: runhidden; RunOnceId: "DelBanOut6"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""netvis-ban-in-v6"""; \
    Flags: runhidden; RunOnceId: "DelBanIn6"

[Code]
// Running the setup again when netvis is already installed offers to remove
// it, rather than silently reinstalling over the top. People keep the
// installer in Downloads and reach for it when they want the program gone -
// expecting them to know it lives in Add/Remove Programs is optimistic.
function ExistingUninstaller(): String;
var
  Key, Value: String;
begin
  Result := '';
  Key := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\' +
         '{7B2F5C31-9E4A-4C88-B1D6-3A0E5F2D9C47}_is1';
  // Check both views: a previous version may have registered under either.
  if RegQueryStringValue(HKLM, Key, 'UninstallString', Value) or
     RegQueryStringValue(HKCU, Key, 'UninstallString', Value) then
    Result := RemoveQuotes(Value);
end;

function InitializeSetup(): Boolean;
var
  Uninstaller: String;
  ResultCode: Integer;
begin
  Result := True;
  Uninstaller := ExistingUninstaller();
  if (Uninstaller = '') or (not FileExists(Uninstaller)) then
    Exit;

  case MsgBox('netvis is already installed on this computer.' + #13#10 + #13#10 +
              'Yes  - reinstall or update it' + #13#10 +
              'No   - uninstall it' + #13#10 +
              'Cancel - do nothing',
              mbConfirmation, MB_YESNOCANCEL) of
    IDYES:
      ; // fall through into the normal install
    IDNO:
      begin
        // Hand over to the existing uninstaller and step aside. /NORESTART
        // keeps it from rebooting behind the user's back.
        Exec(Uninstaller, '/NORESTART', '', SW_SHOW, ewWaitUntilTerminated, ResultCode);
        Result := False;
      end;
  else
    Result := False;
  end;
end;

// netvis normally lives in the tray, so a plain install would try to
// overwrite an exe that's still running and fail. Close it first, both when
// installing and when uninstalling.
procedure StopNetvis();
var
  ResultCode: Integer;
begin
  // Close the tray app, THEN stop the WinDivert kernel driver it was using.
  // Order matters: while netvis holds a WinDivert handle the driver won't
  // stop, and while the driver is running WinDivert64.sys stays locked and
  // can't be replaced - which is exactly the "DeleteFile failed; Access is
  // denied" an in-place update hits when it tries to overwrite the .sys.
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM netvis.exe /F /T',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(800);
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop WinDivert', '', SW_HIDE,
       ewWaitUntilTerminated, ResultCode);
  Sleep(1500); // sc returns when the stop is requested, not once it completes
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopNetvis();
  Result := '';
end;

function InitializeUninstall(): Boolean;
begin
  // StopNetvis now closes the app AND stops the WinDivert driver, which is
  // what frees WinDivert64.sys so the folder can be removed without a reboot
  // or leftover files.
  StopNetvis();
  Result := True;
end;

// Settings, the firewall blocklist and the license record live in
// %ProgramFiles%\netvis and are deliberately left behind on uninstall: a
// reinstall then keeps the user's license and their blocked domains. Only
// clear them if the user explicitly asks.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{autopf}\netvis');
    if DirExists(DataDir) then
    begin
      if MsgBox('Also delete your netvis settings and firewall blocklist?' + #13#10 +
                'Keep them if you plan to reinstall.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(DataDir, True, True, True);
    end;
  end;
end;
