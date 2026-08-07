// Minimal thread-safe logger writing to netvis.log next to the exe. GUI
// subsystem apps have no console to print to, and this is what makes the
// block/unblock and startup-failure diagnostics actually visible.
#pragma once
#include <cstdarg>
#include <string>

void LogInit();
void Log(const char* fmt, ...);
