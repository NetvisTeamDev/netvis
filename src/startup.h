// "Run netvis when Windows starts", done the way an elevated app has to:
// a Task Scheduler task registered to run at logon with highest privileges
// (so it launches without a UAC prompt and can open WinDivert). A plain
// HKCU\...\Run entry can't do this - it would start netvis un-elevated and
// everything would silently fail.
//
// Uses the Task Scheduler 2.0 COM API rather than shelling out to
// schtasks.exe, because schtasks' command-line quoting is fragile and was
// the reason an earlier version created a task that never actually ran.
#pragma once

namespace startup {

// True if the netvis logon task exists.
bool IsEnabled();

// Creates (on=true) or removes (on=false) the logon task pointing at the
// current netvis.exe. Returns whether it succeeded.
bool SetEnabled(bool on);

} // namespace startup
