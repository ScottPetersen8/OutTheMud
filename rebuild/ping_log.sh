#!/bin/bash
# Simple network check script
# Logs ping results with time stamps

LOGFILE="ping_results.txt"

while true; do
    echo "$(date) - checking connectivity..." >> $LOGFILE
    if ping -n 1 8.8.8.8 &> /dev/null
    then
        echo "$(date) - Internet: UP" >> $LOGFILE
    else
        echo "$(date) - Internet: DOWN" >> $LOGFILE
    fi
    sleep 60
done
