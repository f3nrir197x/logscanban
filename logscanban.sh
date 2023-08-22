#!/bin/bash

#
# 2023-AUG-22: 
# Added Geo IP location to withpath.txt
# Prerequisite is to have geoiplookup installed:
# apt install geoip-bin
# Added command-line arguments to reduce running time
# usage: logscanban [full|recent]
#

# Check command-line arguments
SCAN_TYPE="full" # Default to full scan
if [ "$1" == "recent" ]; then
    SCAN_TYPE="recent"
elif [ "$1" != "full" ]; then
    echo "Usage: $0 [full|recent]"
    exit 1
fi


# Define a function to extract unique IP addresses from a file
extract_ips() {
    local file_pattern=$1
    for log in $file_pattern; do
        echo "Processing $log..."
        if [[ $log == *"auth.log"* ]]; then
            zcat -f "$log" | grep 'nvalid' | grep -Eo $IP_REGEX | while read -r ip; do
		geo=$(geoiplookup $ip | awk -F":" '{print $2}')
		tstamp=$(date +"%Y-%m-%d | %T")
                echo "$ip | $log |$geo | $tstamp" >> $TEMP_FILE
            done
        elif [[ $log == *"dovecot.log"* ]]; then
            zcat -f "$log" | grep -E 'error|no\ auth' | grep -Eo $IP_REGEX | while read -r ip; do
                geo=$(geoiplookup $ip | awk -F":" '{print $2}')
                tstamp=$(date +"%Y-%m-%d | %T")
                echo "$ip | $log |$geo | $tstamp" >> $TEMP_FILE
            done
        elif [[ $log == *"exim4/mainlog"* ]]; then
            zcat -f "$log" | grep -v 'Connection timed out' | grep -Eo $IP_REGEX | while read -r ip; do
                geo=$(geoiplookup $ip | awk -F":" '{print $2}')
                tstamp=$(date +"%Y-%m-%d | %T")
                echo "$ip | $log |$geo | $tstamp" >> $TEMP_FILE
            done
        elif [[ $log == *"hestia/nginx-access.log"* ]]; then
            zcat -f "$log" | awk '($9 !~ /^"2/ && $9 !~ /^"5/) {print $1}' | grep -Eo $IP_REGEX | while read -r ip; do
                geo=$(geoiplookup $ip | awk -F":" '{print $2}')
                tstamp=$(date +"%Y-%m-%d | %T")
                echo "$ip | $log |$geo | $tstamp" >> $TEMP_FILE
            done
        else
            zcat -f "$log" | grep -Eo $IP_REGEX | while read -r ip; do
                geo=$(geoiplookup $ip | awk -F":" '{print $2}')
                tstamp=$(date +"%Y-%m-%d | %T")
                echo "$ip | $log |$geo | $tstamp" >> $TEMP_FILE
            done
        fi
    done
}

process_logs() {
    local log_dir_pattern=$1
    for log in $log_dir_pattern; do
        zcat -f "$log" | awk '($9 !~ /^2/ && $9 !~ /^5/){print $1}' | grep -Eo $IP_REGEX | while read -r ip; do
            geo=$(geoiplookup $ip | awk -F":" '{print $2}')
            tstamp=$(date +"%Y-%m-%d | %T")
            echo "$ip | $log |$geo | $tstamp" >> $TEMP_FILE
        done
    done
}

### IP_REGEX="([0-9]{1,3}[\.]){3}[0-9]{1,3}"
IP_REGEX="((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
TEMP_FILE=$(mktemp /tmp/tempfile.XXXXXX)
TEMP_FILE_NEW=$(mktemp /tmp/tempfile_new.XXXXXX)
TRAIL=/root/withpath.txt
FILE=/var/log/meinban.txt
EXCLUDE_IP_FILE=/var/log/exclude_ip.txt
EXCLUDE_RANGES="XXX\.YYY\.ZZZ\.|AAA\.BBB\.CCC\.|MM\.NN\.PP\." ###Replace this with the networks to be excluded

# Define log file patterns for full and recent scans
if [ "$SCAN_TYPE" == "full" ]; then
    LOG_FILES=(
        /var/log/nginx/domains/*.error*
        /var/log/nginx/error.log*
        /var/log/apache2/domains/*.error*
        /var/log/apache2/error.log*
        /var/log/auth.log*
        /var/log/dovecot.log*
        /var/log/exim4/mainlog*
        /var/log/exim4/rejectlog*
        /var/log/hestia/nginx-access.log*
        /var/log/hestia/nginx-error.log*
    )
else
    LOG_FILES=(
        /var/log/nginx/domains/*.error.log
        /var/log/nginx/error.log
        /var/log/apache2/domains/*.error.log
        /var/log/apache2/error.log
        /var/log/auth.log
        /var/log/dovecot.log
        /var/log/exim4/mainlog
        /var/log/exim4/rejectlog
        /var/log/hestia/nginx-access.log
        /var/log/hestia/nginx-error.log
    )
fi

# Extract IPs from each log file
for LOG_FILE in "${LOG_FILES[@]}"; do
    extract_ips $LOG_FILE
done

# Check the command-line argument for "full" or "recent"
if [ "$1" == "full" ]; then
    # Full scan: process all logs
    process_logs "/var/log/nginx/domains/*.log*"
    process_logs "/var/log/apache2/domains/*.log*"
elif [ "$1" == "recent" ]; then
    # Recent scan: process only current logs (without .gz extension)
    process_logs "/var/log/nginx/domains/*.log"
    process_logs "/var/log/apache2/domains/*.log"
else
    echo "Usage: $0 [full|recent]"
    exit 1
fi

### Added ban to IPs hitting ssh
lastb | awk {'print $3'} | grep -Eo $IP_REGEX | while read -r ip; do
    geo=$(geoiplookup $ip | awk -F":" '{print $2}')
    tstamp=$(date +"%Y-%m-%d | %T")
    echo "$ip | /var/log/btmp |$geo | $tstamp" >> $TEMP_FILE
done

# Filter known and authorized IPs and create a file with both offending IP addresses and logfile where they were found. Some duplicates may happen
grep -v -f $EXCLUDE_IP_FILE $TEMP_FILE | grep -vE $EXCLUDE_RANGES | sort -u > $TEMP_FILE_NEW

# If recent scan, append only new IPs
if [ "$SCAN_TYPE" == "recent" ]; then
    comm -13 $TRAIL $TEMP_FILE_NEW >> $TRAIL
    awk -F"|" '{print $1}' $TEMP_FILE_NEW | sort -u | comm -13 $FILE - >> $FILE
else
    cat $TEMP_FILE_NEW > $TRAIL
    awk -F"|" '{print $1}' $TEMP_FILE_NEW | sort -u > $FILE
fi

# Remove the temporary files:
rm $TEMP_FILE $TEMP_FILE_NEW
