# LogScanBan

LogScanBan scans the log files of common services on an internet-exposed Linux
server (nginx, Apache, SSH/auth, Dovecot, Exim4, HestiaCP), extracts the IP
addresses behind suspicious activity (failed logins, brute-force attempts,
error-generating requests), and bans them at the firewall level using
**ipset + iptables**.

Bans **expire automatically** after a configurable retention period, so the
ban list stays small and fast no matter how long the server has been running.
Attackers that keep coming back get re-banned immediately, so persistent
offenders are effectively blocked forever, while one-off scanners age out.

---

## How it works

1. **Scan** — the script reads the configured log files and applies a
  per-service filter (e.g. `Invalid user` lines in `auth.log`, non-2xx/5xx
  requests in access logs) to find offending IP addresses. Failed SSH logins
  recorded in `/var/log/btmp` are included via `lastb`.
2. **Filter** — IPs listed in the exclude file, IPs in excluded network
  ranges, and IPs seen fewer than `MIN_HITS` times are dropped.
3. **Record** — surviving IPs are written to two files:
  - `/var/log/meinban.txt` — plain list, one IP per line (this is the file
    you feed to other tools if you don't want the script to manage the
    firewall itself).
  - `/root/withpath.txt` — detailed trail: IP, the log it was found in, its
    GeoIP country, and a timestamp. Entries older than `RETENTION_DAYS` are
    pruned on every run, and `meinban.txt` is rebuilt from this pruned
    trail — that is what keeps the list from growing forever.
4. **Ban** — every IP is added to an ipset named `logscanban` with a TTL of
  `RETENTION_DAYS`. A single iptables rule drops all traffic matching the
  set. If `SUBNET_THRESHOLD` or more distinct IPs come from the same /24,
  the whole /24 is banned with one entry in a second set
  (`logscanban_net`) instead.

### Why ipset instead of one iptables rule per IP?

A chain of individual `iptables -A INPUT -s $IP -j DROP` rules is checked
**sequentially for every packet** — with thousands of bans this measurably
eats CPU. An ipset is a kernel hash table: there is exactly **one** iptables
rule, lookups are O(1), and the kernel removes expired entries by itself.
This is the same mechanism Fail2Ban uses in its ipset mode.

---

## Requirements

- Linux with bash, GNU coreutils, awk, grep (any Debian/Ubuntu-family
  system qualifies; HestiaCP servers are the primary target)
- `ipset` — `apt install ipset`
- `geoip-bin` — `apt install geoip-bin` (provides `geoiplookup` for the
  country column in the trail file; the script still works without it, the
  geo column will just read "unknown")
- Root privileges (reads protected logs, manages iptables/ipset)
- `flock` and `lastb` (part of util-linux, present on virtually every system)

The script uses iptables. On nftables-only systems (no `iptables-nft`
compatibility layer), see "nftables" under *Adapting to your environment*.

---

## Installation

```bash
git clone https://github.com/f3nrir197x/logscanban.git
cd logscanban
chmod +x logscanban.sh
cp logscanban.sh /usr/local/sbin/
apt install ipset geoip-bin
```

Then, **before the first run**, do the three configuration steps below.

---

## Configuration

All settings are at the top of the script.

### 1. Required: exclusions (do this first!)

A badly configured exclusion list is the only way this script can hurt you —
it can ban **your own IP**, your monitoring systems, or your office network.

- `EXCLUDE_IP_FILE` (default `/var/log/exclude_ip.txt`): one IP per line,
  matched **exactly**. Put your home/office IPs and any monitoring probes
  here. Create the file even if it's empty:
  
  ```bash
  cat > /var/log/exclude_ip.txt <<EOF
  203.0.113.10
  198.51.100.25
  EOF
  ```
  
- `EXCLUDE_RANGES`: a regex of network prefixes to skip, anchored at the
  start of the IP. Replace the `XXX\.YYY\.ZZZ\.` placeholders with your real
  networks, e.g. to exclude 10.x.x.x and 192.168.x.x:
  
  ```bash
  EXCLUDE_RANGES="^10\.|^192\.168\."
  ```
  
  **The script will not work correctly until the placeholder is replaced.**
  

> Tip: before letting the script touch the firewall, do a dry run with
> `APPLY_BANS=0` and review `/var/log/meinban.txt`. If your own IP is in
> there, fix the exclusions first.

### 2. Tunables

| Variable | Default | Meaning |
| --- | --- | --- |
| `RETENTION_DAYS` | `14` | How long a ban lives, both in the on-disk lists and in the kernel ipset. Raise for stickier bans, lower for a smaller list. |
| `MIN_HITS` | `1` | How many times an IP must appear across all logs in one run before it is banned. Raise to `2`–`3` to avoid banning a legitimate user for a single typo'd password. |
| `SUBNET_THRESHOLD` | `10` | If this many distinct banned IPs share a /24, the whole /24 is banned with a single entry. Lower = more aggressive. |
| `APPLY_BANS` | `1` | `1` = the script manages ipset/iptables itself. `0` = it only writes the list files and you feed them to Hestia/Fail2Ban/iptables yourself (see *Integrations*). |

### 3. Log paths

The `LOG_PATTERNS` arrays list which logs are scanned. The defaults match a
HestiaCP server (nginx, apache2, auth, dovecot, exim4, hestia). Remove
patterns for services you don't run and add patterns for ones you do —
unknown logs are scanned with a generic "extract every IP" rule, so only add
logs where an appearing IP really is suspicious (error logs, reject logs),
not plain access logs.

---

## Usage

```bash
logscanban.sh recent   # incremental: only new log lines since the last run
logscanban.sh full     # everything, including rotated .gz logs
```

- **`recent`** is what you run from cron. The script remembers a byte offset
  per log file (in `/var/lib/logscanban/offsets/`), so each run reads only
  the bytes appended since last time — runtime stays roughly constant
  regardless of log size. Rotated/truncated files are detected via inode and
  size and re-read from the start automatically.
- **`full`** re-reads all logs including compressed rotations. Use it on
  first deployment and once a day as a safety net; it also resets the
  offsets so nothing is ever missed across rotations.

The first `recent` run after installation reads each live log fully once to
establish the offsets — that one run takes as long as the old script did;
every run after it is fast.

A lock file prevents overlapping runs (a slow `full` can't collide with the
next `recent` from cron); the second invocation simply exits.

### Suggested cron setup

```cron
*/10 * * * * /usr/local/sbin/logscanban.sh recent >/dev/null 2>&1
25 4 * * *   /usr/local/sbin/logscanban.sh full   >/dev/null 2>&1
```

---

## Surviving reboots

ipset contents live in kernel memory and are **lost on reboot**. Two options:

1. **Do nothing** — the on-disk files persist, so the first cron run after
  boot repopulates the set. Acceptable if a few minutes of unbanned window
  after a reboot is fine for you (it usually is).
  
2. **Persist the set** — save and restore it explicitly:
  
  ```bash
  ipset save > /etc/ipset.conf
  ```
  
  and restore at boot before iptables rules load, e.g. with
  `netfilter-persistent` (`apt install ipset-persistent`) or a small
  systemd unit running `ipset restore < /etc/ipset.conf`.
  

The single iptables rule referencing the set also needs to survive reboots —
`iptables-persistent` handles that, or just let the script re-create it on
the first cron run (it checks with `iptables -C` and only inserts the rule
if missing, so it never duplicates).

---

## Integrations (APPLY_BANS=0 mode)

If you prefer the script to only *detect* and let another tool *block*, set
`APPLY_BANS=0` and consume `/var/log/meinban.txt`:

**HestiaCP**

```bash
while read IP; do
    v-add-firewall-ban "$IP"
done < /var/log/meinban.txt
```

**Fail2Ban**

```bash
while read IP; do
    fail2ban-client set <jailname> banip "$IP"
done < /var/log/meinban.txt
```

**Plain iptables** (not recommended at scale — see "Why ipset" above)

```bash
while read IP; do
    iptables -A INPUT -s "$IP" -j DROP
done < /var/log/meinban.txt
```

Note: in this mode the *files* still self-prune after `RETENTION_DAYS`, but
whatever you fed into the other tool does not — unbanning is then that
tool's responsibility.

---

## Files used by the script

| Path | Purpose |
| --- | --- |
| `/var/log/meinban.txt` | Current ban list, one IP per line (rebuilt every run) |
| `/root/withpath.txt` | Detailed trail: `ip \\| source log \\| geo \\| timestamp` |
| `/var/log/exclude_ip.txt` | Your allowlist, one IP per line |
| `/var/lib/logscanban/offsets/` | Per-log read offsets for incremental scans |
| `/var/lib/logscanban/geocache.txt` | Cached GeoIP lookups (one lookup per IP, ever) |
| `/run/logscanban.lock` | Lock file preventing parallel runs |

Everything under `/var/lib/logscanban` can be deleted safely at any time —
the next run rebuilds it (the following `recent` run will be a slow one, as
offsets are re-established).

---

## Adapting to your environment

- **nftables-only systems:** replace the ipset/iptables block with a native
  nft set, which supports timeouts the same way:
  
  ```bash
  nft add table inet filter
  nft add set inet filter logscanban '{ type ipv4_addr; flags timeout; }'
  nft add rule inet filter input ip saddr @logscanban drop
  nft add element inet filter logscanban "{ $IP timeout ${BAN_TIMEOUT}s }"
  ```
  
- **IPv6:** the script currently extracts IPv4 only. For IPv6 you would add
  an IPv6 regex, a `hash:ip family inet6` set, and matching `ip6tables`
  rules.
  
- **btmp growth:** `lastb` reads `/var/log/btmp` in full on older systems.
  Make sure btmp is rotated (Debian/Ubuntu do this by default in
  `/etc/logrotate.conf`); the script also uses `lastb --since` to limit the
  window where util-linux supports it.
  

---

## Verifying it works

```bash
# how many IPs / subnets are currently banned in the kernel
ipset list logscanban   | grep -c '^[0-9]'
ipset list logscanban_net | grep -c '^[0-9]'

# is the firewall rule in place?
iptables -L INPUT -n | grep logscanban

# what was found, where, and when
column -t -s'|' /root/withpath.txt | less

# remove a ban manually (e.g. you banned yourself)
ipset del logscanban 203.0.113.50
# ...and add the IP to /var/log/exclude_ip.txt so it doesn't come back
```

---

## Important considerations before deploying

- **Test exclusions first** (`APPLY_BANS=0`, inspect `meinban.txt`). Locking
  yourself out of a remote server is the main risk. Keep an out-of-band
  console (VNC/IPMI/provider console) available the first days.
- **MIN_HITS=1 is aggressive**: a single failed login bans the IP for the
  full retention period. That's often desirable on a server with no
  interactive users, but raise it if real people log in over SSH/IMAP.
- **Shared/NAT addresses**: banning a /24 (or even a single IP belonging to
  a CGNAT pool or corporate proxy) can block legitimate users sharing that
  address. If your audience sits behind large NATs, raise
  `SUBNET_THRESHOLD` or disable aggregation by setting it very high.
- **This is a complement, not a replacement,** for basics like key-only SSH
  authentication, disabling root login, and keeping services patched.

---

## License

MIT — see [LICENSE](LICENSE).
