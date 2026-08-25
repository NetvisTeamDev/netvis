// Single source of truth for the app version. Bump ONLY here on each release:
// build_installer.bat reads this and passes it to Inno Setup, and deploy.bat
// reads it for the update manifest - so the exe, the installer and the update
// all get the same version automatically, and can never disagree. The updater
// compares the manifest's version against this string to decide whether a
// newer build exists.
#pragma once
#define NETVIS_VERSION "1.0.2"
