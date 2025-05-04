#!/bin/bash

# Defaults
REPEAT=1
PORT=80
SKIP_INSTRUCTION=false

# Usage function
usage() {
    echo "Usage: $0 <TARGET_IP> [-r REPEAT_COUNT] [-p PORT] [-i]"
    echo "  <TARGET_IP>     The IP address of the target computer."
    echo "  -r              Number of times to repeat the ICMP and TCP requests (default: 1)"
    echo "  -p              TCP port to connect to (default: 80)"
    echo "  -i              Skip the instructions for tcpdump (optional)"
    echo "Example: $0 192.168.1.10 -r 5 -p 8080 -i"
    exit 1
}

# Parse arguments
if [ -z "$1" ]; then
    echo -e "You must provide a target IP address, dummy!"
    usage
fi

TARGET_IP="$1"
shift           # Remove the first argument (TARGET_IP)

# Parse optional arguments
while getopts "r:p:i" opt; do
    case "$opt" in
        r) REPEAT="$OPTARG" ;;
        p) PORT="$OPTARG" ;;
        i) SKIP_INSTRUCTION=true ;;
        *) usage ;;
    esac
done

# Monitoring instructions
if [ "$SKIP_INSTRUCTION" = false ]; then
    echo "Before continuing, please run the following commands on the target computer:"
    echo " - sudo tcpdump ip proto \\icmp"
    echo " - sudo tcpdump port $PORT and '(tcp-syn|tcp-ack)!=0'"
    read -p "Press Enter when ready to proceed..."
fi

# Validate IP address format
echo "[*] Target: $TARGET_IP"
echo "[*] Repeat: $REPEAT"
echo "[*] TCP Port: $PORT"

# Send ICMP Echo Request and TCP request
for ((i=1; i<=REPEAT; i++)); do
    echo -e "\n[+] Attempt #$i"

    echo "[*] Sending ICMP Echo Request to $TARGET_IP..."
    ping -c 1 "$TARGET_IP"

    echo "[*] Sending TCP request to $TARGET_IP on port $PORT..."
    nc "$TARGET_IP" "$PORT"
done
