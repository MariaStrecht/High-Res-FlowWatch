#!/bin/bash

# Check if the PID argument is provided
if [ -z "$1" ]; then
  echo "Usage: ./memory_monitor.sh <PID>"
  exit 1
fi

# Set the process ID (PID) from the argument
PID=$1

# Set the interval between measurements in seconds
INTERVAL=5

# Set the total number of measurements to take
# COUNT=10

# Set the output file path
OUTPUT_FILE="memory_usage.txt"

# Header for the output file
echo "Timestamp,Memory Usage (KB)" > "$OUTPUT_FILE"

# Loop to monitor memory usage
while true; do
  # Get the current timestamp
  TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

  # Use the ps command to retrieve memory usage of the process
  MEMORY_USAGE=$(ps -p $PID -o rss=)

  # Append the timestamp and memory usage to the output file
  echo "$TIMESTAMP,$MEMORY_USAGE" >> "$OUTPUT_FILE"

  # Wait for the specified interval before the next measurement
  sleep $INTERVAL
done
