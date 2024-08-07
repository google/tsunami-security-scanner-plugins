#!/bin/bash

while [ ! -f /lockconfig/lock ]; do
  echo "Waiting for the file to be created by cluster"
  sleep 2
done

# Define the Gunicorn start command
GUNICORN_CMD="gunicorn -w 3 --bind 0.0.0.0:5000 --access-logfile -  entrypoint:app"

# Function to start Gunicorn
start_gunicorn() {
    echo "Starting Gunicorn..."
    $GUNICORN_CMD
}

# Function to monitor and restart Gunicorn if it exits
monitor_gunicorn() {
    while true; do
        start_gunicorn

        # Wait for Gunicorn to exit
        wait $!

        # Log the exit and attempt a restart
        echo "Gunicorn exited. Restarting..."
        sleep 1  # Optional sleep before restarting
    done
}

# Start monitoring Gunicorn
monitor_gunicorn
