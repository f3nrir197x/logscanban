# LogScanBan

LogScanBan is a script designed to enhance the security of your server by detecting and blocking IP addresses involved in suspicious activities such as brute force attacks. It scans log files from various services, including nginx, apache, auth, dovecot, exim4, and hestia, to identify unique IP addresses. It then excludes certain IP addresses and ranges, and generates a consolidated report of the remaining IP addresses, which can be used to update firewall rules.

## Features

- Scans log files from various services, including nginx, apache, auth, dovecot, exim4, and hestia.
- Detects and blocks IP addresses involved in suspicious activities.
- Excludes certain IP addresses and ranges.
- Generates a consolidated report of blacklisted IP addresses.
- Handles errors and logs the processing of each file.
- Can be easily extended to process additional log files.

## Installation

1. Clone the repository: `git clone https://github.com/f3nrir197x/LogScanBan.git`
2. Ensure you have the necessary permissions to run the script.
3. Update the `EXCLUDE_IP_FILE` and `EXCLUDE_RANGES` variables in the script to match your requirements.
4. Make the script executable: chmod 
5. Set up a cron job to run the script periodically.

## Usage

1. Run the script manually: `./logscanban.sh`
2. To view the list of blacklisted IP addresses, check the `/var/log/meinban.txt` file.
3. Customize the exclusion rules in the `/var/log/exclude_ip.txt` file. This file is a text file with one IP address per line.
4. Adjust the log file paths in the script to match your server's configuration.
5. Examples of using the output with Hestia, Fail2Ban, and IPTables are provided in the script comments.

### Hestia

To use the output of this script with Hestia, you can add the extracted IP addresses to Hestia's firewall ban list:

```bash
while read IP; do
    v-add-firewall-ban $IP
done < /var/log/meinban.txt
```

### Fail2Ban

To use the output of this script with Fail2Ban, you can add the extracted IP addresses to Fail2Ban's jail:

```bash
while read IP; do
    fail2ban-client set <jailname> banip $IP
done < /var/log/meinban.txt
```

Replace `<jailname>` with the name of your Fail2Ban jail.

### IPTables

To use the output of this script with IPTables, you can add the extracted IP addresses to an IPTables rule:

```bash
while read IP; do
    iptables -A INPUT -s $IP -j DROP
done < /var/log/meinban.txt
```

## Changes from Previous Version

- Added error handling for each operation.
- Encapsulated repetitive tasks into functions.
- Added logging for each file being processed.
- Added a success message at the end of the script.

## Contributing

Contributions are welcome! If you encounter any issues or have suggestions for improvements, please submit a pull request or open an issue on the GitHub repository.

## License

This project is licensed under the [MIT License](LICENSE).
