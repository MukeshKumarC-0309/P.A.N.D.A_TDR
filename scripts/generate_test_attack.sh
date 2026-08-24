#!/usr/bin/env bash
# Run this ON THE ATTACKER VM (source IP 10.0.2.3).
#
# Generates a coordinated, time-aligned attack so the correlation layer has ONE
# real positive to validate against: an SSH hit on the Cowrie honeypot AND a
# network failed-logon on the Windows box, from the same source IP, seconds
# apart -> well inside the HIGH-tier window (IP match, 0-3 min).
#
# The Windows hit MUST be over the network (SMB here) so the 4625 carries a real
# Source_Network_Address (a Type 3 logon). A local console attempt would show no
# source IP -- the 4624 lesson.
#
# Prereqs:  sudo apt install -y sshpass smbclient
set -u

# ---- EDIT THESE for your lab ----
COWRIE_HOST="10.0.2.4"      # honeypot host (SSH port 22 redirects to Cowrie 2222)
WINDOWS_HOST="10.0.2.15"    # Windows VM
USERNAME="admin"
WRONG_PASS="Wrongpass123!"
# ---------------------------------

echo "[*] attack start: $(date -u +%FT%TZ)   (this VM's source IP should be 10.0.2.3)"

echo "[*] 1/2 Cowrie SSH hit -> ${USERNAME}@${COWRIE_HOST}"
sshpass -p "${WRONG_PASS}" ssh \
    -o StrictHostKeyChecking=no -o ConnectTimeout=8 \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    "${USERNAME}@${COWRIE_HOST}" "whoami; exit" 2>/dev/null
echo "    cowrie hit done:  $(date -u +%FT%TZ)"

echo "[*] 2/2 Windows network failed-logon (SMB) -> ${WINDOWS_HOST}"
smbclient -L "//${WINDOWS_HOST}" -U "${USERNAME}%${WRONG_PASS}" -m SMB3 2>/dev/null
echo "    windows hit done: $(date -u +%FT%TZ)"

echo "[*] Both hits are seconds apart -> inside the 0-3 min HIGH window."
echo "[*] NEXT: export the fresh Cowrie session to a JSON file (one event per line),"
echo "         then run validate_correlation.py on the PANDA host pointing COWRIE_LOG at it."
