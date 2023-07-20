#!/bin/bash

# Define a function to extract unique IP addresses from a file
# This version outputs the 
extract_ips() {
    local file_pattern=$1
    for log in $file_pattern; do
        echo "Processing $log..."
        if [[ $log == *"auth.log"* ]]; then
            zcat -f "$log" | grep 'nvalid' | grep -Eo $IP_REGEX | while read -r ip; do
                echo "$ip | $log" >> $TEMP_FILE
            done
        elif [[ $log == *"dovecot.log"* ]]; then
            zcat -f "$log" | grep -E 'error|no\ auth' | grep -Eo $IP_REGEX | while read -r ip; do
                echo "$ip | $log" >> $TEMP_FILE
            done
        elif [[ $log == *"exim4/mainlog"* ]]; then
            zcat -f "$log" | grep -v 'Connection timed out' | grep -Eo $IP_REGEX | while read -r ip; do
                echo "$ip | $log" >> $TEMP_FILE
            done
        elif [[ $log == *"hestia/nginx-access.log"* ]]; then
            zcat -f "$log" | awk '($9 !~ /^"2/ && $9 !~ /^"5/) {print $1}' | grep -Eo $IP_REGEX | while read -r ip; do
                echo "$ip | $log" >> $TEMP_FILE
            done
        else
            zcat -f "$log" | grep -Eo $IP_REGEX | while read -r ip; do
                echo "$ip | $log" >> $TEMP_FILE
            done
        fi
    done
}

process_logs() {
    local log_dir_pattern=$1
    for log in $log_dir_pattern; do
        zcat -f "$log" | awk '($9 !~ /^2/ && $9 !~ /^5/){print $1}' | grep -Eo $IP_REGEX | while read -r ip; do
            echo "$ip | $log" >> $TEMP_FILE
        done
    done
}

IP_REGEX="((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
TEMP_FILE=$(mktemp /tmp/tempfile.XXXXXX)
TRAIL=~/withpath.txt
FILE=/var/log/meinban.txt
EXCLUDE_IP_FILE=/var/log/exclude_ip.txt
EXCLUDE_RANGES="XXX\.YYY\.ZZZ\.|AAA\.BBB\.CCC\.|MM\.NN\.PP\." ###Replace this with the networks to be excluded

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

# Extract IPs from each log file
for LOG_FILE in "${LOG_FILES[@]}"; do
    extract_ips $LOG_FILE
done

# Call the function for nginx and apache logs
process_logs "/var/log/nginx/domains/*.log*"
process_logs "/var/log/apache2/domains/*.log*"

### Added ban to IPs hitting ssh
lastb | awk {'print $3'} | grep -Eo $IP_REGEX | while read -r ip; do
    echo "$ip | /var/log/btmp" >> $TEMP_FILE
done

### Create a file with both offending IP addresses and logfile where they were found. Some duplicates may appear
grep -v -f $EXCLUDE_IP_FILE $TEMP_FILE | grep -vE $EXCLUDE_RANGES | sort -u > $TRAIL

### Exclude IPs from the exclude file and the specified ranges, then sort, deduplicate and write to the final file:
cat $TRAIL | awk -F"|" '{print $1}' | sort -u > $FILE

# Remove the temporary file:
rm $TEMP_FILE
