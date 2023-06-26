# logscanban
```
# LogScanBan

LogScanBan is a script designed to enhance the security of your server by detecting and blocking IP addresses involved in brute force attacks. It scans log files from various services, such as Apache and Nginx, to identify suspicious activity and automatically blacklist the offending IP addresses.

## Features

- Detects brute force attacks from log files of popular web servers.
- Automatically blocks malicious IP addresses.
- Provides customizable exclusion rules for IP ranges.
- Generates a consolidated report of blacklisted IP addresses.

## Installation

1. Clone the repository: `git clone https://github.com/f3nrir197x/LogScanBan.git`
2. Ensure you have the necessary permissions to run the script.
3. Modify the configuration parameters in the script according to your requirements.
4. Set up a cron job to run the script periodically.

## Usage

1. Run the script manually: `logscanban.sh`
2. To view the list of blacklisted IP addresses, check the `/var/log/meinban.txt` file.
3. Customize the exclusion rules in the `/var/log/exclude_ip.txt` file. File is a text file with one ip address per line.
4. Adjust the log file paths in the script to match your server's configuration.

## Contributing

Contributions are welcome! If you encounter any issues or have suggestions for improvements, please submit a pull request or open an issue on the GitHub repository.

## License

This project is licensed under the [MIT License](LICENSE).
```
