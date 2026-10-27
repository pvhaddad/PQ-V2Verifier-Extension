#!/bin/bash
# Refuse to start a trial batch if the kernel would clamp the receiver's SO_RCVBUF request.
# REQUIRED must match rcvbuf_size in Vehicle::receive() (src/Vehicle.cpp: 32 * 1024 * 1024).
# Sourced by the trial runners before any config is written or any trial starts.
# Persistent setting: /etc/sysctl.d/99-pq-v2verifier.conf (a runtime sysctl -w reset on reboot
# after Phase 4 and silently caused datagram loss in a later smoke test).
REQUIRED_RMEM_MAX=33554432
current_rmem_max=$(cat /proc/sys/net/core/rmem_max)
if (( current_rmem_max < REQUIRED_RMEM_MAX )); then
    cat >&2 <<MSG
============================================================================
ABORTING: net.core.rmem_max=$current_rmem_max is below required $REQUIRED_RMEM_MAX.
The receiver's 32 MiB SO_RCVBUF request would be silently clamped, and flood
trials would lose datagrams (showing up only as INCOMPLETE RUN afterwards).
No trials were started. Fix (persistent across reboots):
  /etc/sysctl.d/99-pq-v2verifier.conf  ->  net.core.rmem_max = $REQUIRED_RMEM_MAX
  sudo sysctl --system
============================================================================
MSG
    exit 1
fi
echo "[rcvbuf check] net.core.rmem_max=$current_rmem_max (>= $REQUIRED_RMEM_MAX) - OK"
