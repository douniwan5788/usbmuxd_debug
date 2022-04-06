#!/bin/bash

export PATH="$PATH:/Applications/Wireshark.app/Contents/MacOS/tshark"

# Parameters
socket="/var/run/usbmuxd"
dump=$1

# Extract repetition
port=9876
source_socket="$(dirname "${socket}")/$(basename "${socket}").orig"

# Move socket files
sudo mv "${socket}" "${source_socket}"

function recover() {
    echo "Recover"
    # kill socat
    jobs -p
    sudo kill $(jobs -p)

    sudo mv ${source_socket} ${socket}
}

trap recover EXIT

# Setup pipe over TCP that we can tap into
socat -t100 "TCP-LISTEN:${port},reuseaddr,fork" "UNIX-CONNECT:${source_socket}" &
sudo socat -t100 "UNIX-LISTEN:${socket},mode=777,reuseaddr,fork" "TCP:localhost:${port}" &

echo "Started"
# # Record traffic
tshark -i lo0 -w "${dump}" -F pcapng "dst port ${port} or src port ${port}"
# or wait forever and use wireshark
# while :; do sleep 2073600; done