#!/usr/bin/env bash
#
# The server half of deploy.ps1. Copied over with scp and then run by
# name, rather than passed inline to ssh: Windows PowerShell mangles quotes
# inside multi-line native-command arguments, and piping it to `bash -s`
# instead would tie up stdin - which sudo needs if it wants a password.
set -e

SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO=sudo

# Fail with something readable rather than a bare "mv: no such file".
if [ ! -d /opt/netvis ]; then
  echo "ERROR: /opt/netvis does not exist - setup-server.sh has not run successfully yet." >&2
  exit 1
fi
if [ ! -f /etc/systemd/system/netvis-licensing.service ]; then
  echo "ERROR: the netvis-licensing service is not installed - re-run setup-server.sh." >&2
  exit 1
fi
if [ ! -f /tmp/licensing.new ]; then
  echo "ERROR: /tmp/licensing.new is missing - the upload did not arrive." >&2
  exit 1
fi

echo "-- stopping service"
$SUDO systemctl stop netvis-licensing || true
$SUDO mv /tmp/licensing.new /opt/netvis/licensing
$SUDO chmod +x /opt/netvis/licensing

$SUDO chown -R netvis:netvis /opt/netvis

echo "-- starting service"
$SUDO systemctl start netvis-licensing
sleep 1
if ! $SUDO systemctl is-active --quiet netvis-licensing; then
  echo "ERROR: the service did not stay running. Last log lines:" >&2
  $SUDO journalctl -u netvis-licensing -n 20 --no-pager >&2
  exit 1
fi
echo "-- service is running"
