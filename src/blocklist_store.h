// The user-editable firewall blocklist: the domains you've added by hand or
// imported, persisted to C:\Program Files\netvis\blocklist.db so they
// survive restarts and live independently of the exe folder.
//
// Note on the format: this is a plain UTF-8, one-domain-per-line file (with
// '#' comment lines), not a real SQLite database despite the .db name -
// pulling the SQLite engine into this dependency-free build wasn't worth it
// for what is just a flat list of domains. The public surface here is small
// enough that swapping in real SQLite later would be a localized change.
#pragma once
#include <string>
#include <vector>

namespace blocklist_store {

// Full path to blocklist.db, creating C:\Program Files\netvis if needed.
std::string DbPath();

// Loads the saved user domains (lowercased, de-duplicated on save).
std::vector<std::string> Load();

// Overwrites blocklist.db with `domains` (plus a provenance header).
void Save(const std::vector<std::string>& domains);

// Parses domains out of an arbitrary text file for import: lines starting
// with '#' are comments, blank lines are skipped, otherwise the whole
// trimmed line is taken as a domain. Handles "0.0.0.0 domain" / "127.0.0.1
// domain" hosts-file style lines by taking the last whitespace-separated
// token.
std::vector<std::string> ParseFile(const std::string& path);

} // namespace blocklist_store
