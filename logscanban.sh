#!/bin/bash

# Define a function to extract unique IP addresses from a file
extract_ips() {
    local file=$1
    echo "Processing $file..."

    # Define the command to extract IPs based on the file type
    local cmd
    if [[ $file == *"auth.log"* ]]; then
        cmd="zcat -f $file | grep 'nvalid' | grep -Eo $IP_REGEX"
    elif [[ $file == *"dovecot.log"* ]]; then
        cmd="zcat -f $file | grep -E 'error|no\ auth' | grep -Eo $IP_REGEX"
    elif [[ $file == *"exim4/mainlog"* ]]; then
        cmd="zcat -f $file | grep -v 'Connection timed out' | grep -Eo $IP_REGEX"
    elif [[ $file == *"exim4/rejectlog"* ]]; then
        cmd="zcat -f $file | grep -v warez.pe | grep -Eo $IP_REGEX"
    elif [[ $file == *"hestia/nginx-access.log"* ]]; then
        cmd="zcat -f $file | awk '($9 !~ /^\"2/ && $9 !~ /^\"5/) {print $1}' | grep -Eo $IP_REGEX"
    else
        cmd="zcat -f $file | grep -Eo $IP_REGEX"
    fi

    # Run the command and append the output to the temporary file
    local ips=$($cmd)
    if [ $? -ne 0 ]; then
        echo "Error running command: $cmd"
        exit 1
    fi

    echo "$ips" | sort -u >> $TEMP_FILE
    if [ $? -ne 0 ]; then
        echo "Error writing to $TEMP_FILE"
        exit 1
    fi
}

# Function to process nginx/apache logs
process_logs() {
    local log_dir=$1
    local logs=$(ls $log_dir | grep -v -E '\.error\.log')
    if [ -n "$logs" ]; then
        zcat -f $logs | awk '($9 !~ /^2/ && $9 !~ /^5/){print $1}' | sort -u >> $TEMP_FILE
        if [ $? -ne 0 ]; then
            echo "Error processing logs from $log_dir"
            exit 1
        fi
    fi
}

# Define a function to handle error
handle_error() {
    if [ $? -ne 0 ]; then
        echo "Error: $1"
        exit 1
    fi
}

IP_REGEX="([0-9]{1,3}[\.]){3}[0-9]{1,3}"
TEMP_FILE=$(mktemp /tmp/tempfile.XXXXXX)
handle_error "Failed to create temporary file"

FILE=/var/log/meinban.txt
EXCLUDE_IP_FILE=/var/log/exclude_ip.txt
EXCLUDE_RANGES="AA\.BB\.CC\.|XX\.YY\.ZZ\.|RRR\.SSS\.TTT\." ### Replace the ranges with the one you want to exclude

LOG_FILES=(
    "/var/log/nginx/domains/*.error*"
    "/var/log/nginx/error.log*"
    "/var/log/apache2/domains/*.error*"
    "/var/log/apache2/error.log*"
    "/var/log/auth.log*"
    "/var/log/dovecot.log*"
    "/var/log/exim4/mainlog*"
    "/var/log/exim4/rejectlog*"
    "/var/log/hestia/nginx-access.log*"
    "/var/log/hestia/nginx-error.log*"
)

# Extract IPs from each log file
for LOG_FILE in "${LOG_FILES[@]}"; do
    extract_ips $LOG_FILE
done

# Call the function for nginx and apache logs
process_logs "/var/log/nginx/domains/*.log*"
process_logs "/var/log/apache2/domains/*.log*"

# Check logs for hestia/nginx || Removed as it is already handled
### zcat -f /var/log/hestia/nginx-access.log* | sed 's/\"//g' | awk '$9 !="200" {print $1}' | grep -Eo $IP_REGEX | sort -u >> $TEMP_FILE

### Added ban to IPs hitting ssh
lastb | awk {'print $3'} | grep -Eo $IP_REGEX | sort -u >> $TEMP_FILE

# Exclude IPs from the exclude file and the specified ranges, then sort, deduplicate and write to the final file
grep -v -f $EXCLUDE_IP_FILE $TEMP_FILE | grep -vE $EXCLUDE_RANGES | sort -u > $FILE
handle_error "Failed to write to $FILE"

# Remove the temporary file
rm $TEMP_FILE
handle_error "Failed to remove temporary file"

echo "Script completed successfully"
