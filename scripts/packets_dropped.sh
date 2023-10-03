#!/bin/bash

# Network interface to monitor
interface="ens192"

# Path to store the packet count
countFile="../archive/packet_count.txt"

# Get packet count
getPacketCount() {
    # number of packets received and transmitted
    rx_packets=$(cat /sys/class/net/ens192/statistics/rx_packets)
    tx_packets=$(cat /sys/class/net/ens192/statistics/tx_packets)
    
    packetCount=$((rx_packets + tx_packets))

    # Store the value in a file
    echo $packetCount > $countFile
}

# Function to calculate the number of packets received and transmitted in a day
calculatePackets() {
    # Get the packet count at the start and end of the day
    startCount=$(cat $countFile)
    getPacketCount
    endCount=$(cat $countFile)
    
    # Calculate the packets received and transmitted during the day
    overall=$((endCount - startCount))
    
    # Print the result
    echo "Packets exchanged today: $overall"
}

# Check if the count file exists, otherwise create it
if [ ! -f $countFile ]; then
    touch $countFile
fi

# Continuous monitoring loop
while true; do
    # Check if it's the start of the day
    if [ $(date '+%H:%M') == "01:59" ]; then
        getPacketCount
        echo "Start of the day packet count stored."
    fi

    # Check if it's the end of the day
    if [ $(date '+%H:%M') == "02:00" ]; then
        calculatePackets
    fi

    # Wait for some time before checking again (adjust the sleep duration as needed)
    sleep 60
done
