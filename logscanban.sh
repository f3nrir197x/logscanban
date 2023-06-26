#!/bin/bash

TEMP_FILE=$(mktemp /tmp/tempfile.XXXXXX)
FILE=/var/log/meinban.txt
EXCLUDE_IP_FILE=/var/log/exclude_ip.txt
EXCLUDE_RANGES="AA\.BB\.CC\.|XX\.YY\.ZZ\.|RRR\.SSS\.TTT\." ### Replace the ranges with the one you want to exclude

NGINX_LOGS=$(ls /var/log/nginx/domains/*.log* | grep -v -E '\.error\.log')
if [ -n "$NGINX_LOGS" ]; then
    zcat -f $NGINX_LOGS | awk '$9 != 200 && $9 != 500 {print $1}' | sort -u >> $TEMP_FILE
fi
zcat -f /var/log/nginx/domains/*.error* | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort -u >> $TEMP_FILE
zcat -f /var/log/nginx/error.log* | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort -u >> $TEMP_FILE

APACHE2_LOGS=$(ls /var/log/apache2/domains/*.log* | grep -v -E '\.error\.log')
if ls $APACHE2_LOGS 1> /dev/null 2>&1; then
    zcat -f $APACHE2_LOGS | awk '$9 != 200 && $9 != 500 {print $1}' | sort -u >> $TEMP_FILE
fi
zcat -f /var/log/apache2/domains/*.error* | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort -u >> $TEMP_FILE
zcat -f /var/log/apache2/error.log* | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort -u >> $TEMP_FILE

zcat -f /var/log/auth.log* | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort -u >> $TEMP_FILE

zcat -f /var/log/dovecot.log* | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort -u >> $TEMP_FILE

zcat -f /var/log/exim4/mainlog* | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort -u >> $TEMP_FILE
zcat -f /var/log/exim4/rejectlog* | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort -u >> $TEMP_FILE

zcat -f /var/log/hestia/nginx-access.log* | sed 's/\"//g' | awk '$9 !="200" {print $1}' | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort -u >> $TEMP_FILE
zcat -f /var/log/hestia/nginx-error.log* | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort -u >> $TEMP_FILE

### Exclude IPs from the exclude file and the specified ranges, then sort, deduplicate and write to the final file:
grep -v -f $EXCLUDE_IP_FILE $TEMP_FILE | grep -vE $EXCLUDE_RANGES | sort -u > $FILE

# Remove the temporary file:
rm $TEMP_FILE
