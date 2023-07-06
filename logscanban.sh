#!/bin/bash

IP_REGEX="([0-9]{1,3}[\.]){3}[0-9]{1,3}"
TEMP_FILE=$(mktemp /tmp/tempfile.XXXXXX)
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

for LOG_FILE in "${LOG_FILES[@]}"; do
    zcat -f $LOG_FILE | grep -Eo $IP_REGEX | sort -u >> $TEMP_FILE
done

NGINX_LOGS=$(ls /var/log/nginx/domains/*.log* | grep -v -E '\.error\.log')
if [ -n "$NGINX_LOGS" ]; then
    zcat -f $NGINX_LOGS | awk '$9 != 200 && $9 != 500 {print $1}' | sort -u >> $TEMP_FILE
fi

APACHE2_LOGS=$(ls /var/log/apache2/domains/*.log* | grep -v -E '\.error\.log')
if ls $APACHE2_LOGS 1> /dev/null 2>&1; then
    zcat -f $APACHE2_LOGS | awk '$9 != 200 && $9 != 500 {print $1}' | sort -u >> $TEMP_FILE
fi

zcat -f /var/log/hestia/nginx-access.log* | sed 's/\"//g' | awk '$9 !="200" {print $1}' | grep -Eo $IP_REGEX | sort -u >> $TEMP_FILE

### Added ban to IPs hitting ssh
lastb | awk {'print $3'} | grep -Eo $IP_REGEX | sort -u >> $TEMP_FILE

### Exclude IPs from the exclude file and the specified ranges, then sort, deduplicate and write to the final file:
grep -v -f $EXCLUDE_IP_FILE $TEMP_FILE | grep -vE $EXCLUDE_RANGES | sort -u > $FILE

# Remove the temporary file:
rm $TEMP_FILE
