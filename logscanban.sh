#!/bin/bash
#
# logscanban.sh (improved)
#
# Changes vs the original, and the reasoning behind each:
#
#  1. ipset WITH TIMEOUTS instead of one iptables rule per IP.
#     With "iptables -A INPUT -s $IP -j DROP" the kernel checks every packet
#     against every rule sequentially -> cost grows linearly with the ban list.
#     An ipset is a hash table: ONE iptables rule, O(1) lookup, and the
#     "timeout" option makes entries expire automatically, so the kernel-side
#     list can never grow forever. Re-adding an IP refreshes its timer, so
#     attackers that keep coming back stay banned.
#
#  2. AUTOMATIC PRUNING of the on-disk lists.
#     The trail file (withpath.txt) already contains timestamps; we now use
#     them to drop entries older than RETENTION_DAYS and rebuild meinban.txt
#     from what remains. Permanently banning is mostly wasted effort anyway:
#     attack IPs are largely rotated cloud/botnet addresses that go quiet
#     within days, so an expiring list keeps ~the same protection at a
#     fraction of the size.
#
#  3. DEDUPLICATE BEFORE geoiplookup, plus a persistent geo cache.
#     The original called geoiplookup + date once PER MATCHED LOG LINE
#     (two subprocesses per line, including duplicates). That was very
#     likely the main CPU cost. Now we extract all IPs first, sort -u,
#     and look each unique IP up exactly once. Results are cached in
#     $GEO_CACHE so subsequent runs don't even do that.
#
#  4. INCREMENTAL "recent" SCANS using byte offsets.
#     In recent mode we remember how far into each live log we read last
#     time (per-file offset + inode). Next run we only read the NEW bytes.
#     If the inode changed or the file shrank (logrotate), we start from 0.
#     This makes frequent cron runs cheap even with large logs.
#
#  5. /24 SUBNET AGGREGATION.
#     If many distinct IPs from the same /24 are caught, the whole subnet
#     gets one hash:net entry instead of N individual ones. Shrinks the set
#     and also pre-blocks the attacker's neighbours, which is usually what
#     you want for botnet ranges. Tune SUBNET_THRESHOLD to taste.
#
#  6. EXACT-MATCH EXCLUSIONS.
#     The original "grep -v -f exclude_ip.txt" did substring matching:
#     excluding 1.2.3.4 would also (silently) exclude 1.2.3.45 and
#     11.2.3.4. We now match the IP field exactly.
#
#  7. flock LOCKING.
#     If a full scan is still running when cron fires the next recent scan,
#     the two no longer trample each other's temp/state files.
#
#  8. MINIMUM HIT THRESHOLD (optional).
#     MIN_HITS lets you require an IP to appear N times before banning,
#     reducing false positives from one-off scanners or typo'd passwords.
#     Default 1 = same behaviour as before.
#
#  9. safer temp handling (mktemp -d + trap cleanup, even on error/ctrl-c),
#     and "set -u" to catch unset-variable bugs.
#
# Prerequisites:
#   apt install geoip-bin ipset
#
# Usage: logscanban.sh [full|recent]
#   full   - scan all logs including rotated/compressed ones
#   recent - scan only live logs, and only the bytes added since last run

set -u

###############################################################################
# CONFIGURATION - adjust to your environment
###############################################################################

RETENTION_DAYS=14            # drop list entries older than this
BAN_TIMEOUT=$((RETENTION_DAYS * 86400))  # ipset entry lifetime, in seconds
MIN_HITS=1                   # appearances required before an IP is banned
SUBNET_THRESHOLD=10          # distinct IPs from one /24 -> ban whole /24
APPLY_BANS=1                 # 1 = manage ipset/iptables directly from here;
                             # 0 = only write the files (old behaviour) if you
                             #     prefer to feed Hestia/Fail2Ban yourself

TRAIL=/root/withpath.txt             # detailed report: ip | log | geo | time
FILE=/var/log/meinban.txt            # plain list of banned IPs
EXCLUDE_IP_FILE=/var/log/exclude_ip.txt   # one IP per line, exact match
EXCLUDE_RANGES="^XXX\.YYY\.ZZZ\.|^AAA\.BBB\.CCC\."  # regex of prefixes to skip
                             # NOTE: anchored with ^ so "10.20." cannot
                             # accidentally match "110.20." anymore.

STATE_DIR=/var/lib/logscanban        # offsets + geo cache live here
GEO_CACHE=$STATE_DIR/geocache.txt    # "ip<TAB>geo" pairs, reused across runs
LOCK_FILE=/run/logscanban.lock

IPSET_NAME=logscanban                # hash:ip set for individual addresses
IPSET_NET_NAME=logscanban_net        # hash:net set for aggregated /24s

# Anchored IP regex (word boundaries) so we never grab fragments of longer
# numeric strings.
IP_REGEX="\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"

###############################################################################
# ARGUMENTS / SETUP
###############################################################################

SCAN_TYPE="${1:-full}"
if [[ "$SCAN_TYPE" != "full" && "$SCAN_TYPE" != "recent" ]]; then
    echo "Usage: $0 [full|recent]" >&2
    exit 1
fi

mkdir -p "$STATE_DIR/offsets"
touch "$GEO_CACHE" "$TRAIL" "$FILE"
[[ -f "$EXCLUDE_IP_FILE" ]] || touch "$EXCLUDE_IP_FILE"

# --- Locking: refuse to run twice in parallel (reason #7) -------------------
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "Another logscanban run is in progress; exiting." >&2
    exit 0
fi

# --- Temp workspace, cleaned up automatically on ANY exit (reason #9) -------
WORKDIR=$(mktemp -d /tmp/logscanban.XXXXXX)
trap 'rm -rf "$WORKDIR"' EXIT

RAW_IPS="$WORKDIR/raw_ips.txt"           # "ip<TAB>logfile", one per match
CANDIDATES="$WORKDIR/candidates.txt"     # unique ip+log after filtering
NEW_BANS="$WORKDIR/new_bans.txt"         # final unique IPs this run
: > "$RAW_IPS"

###############################################################################
# LOG READING
###############################################################################

# read_log <file>
# Emits the (new) content of a log file on stdout.
#  - .gz files are zcat'd in full (only reached in full scans).
#  - In recent mode, plain files are read from the byte offset we stored on
#    the previous run, and the offset is updated afterwards (reason #4).
#  - In full mode, plain files are read entirely and the offset is reset to
#    the file's current size, so the next recent run continues from there.
read_log() {
    local log=$1
    if [[ "$log" == *.gz ]]; then
        zcat -f -- "$log"
        return
    fi

    # Key the offset file on the log path (slashes -> underscores).
    local key=${log//\//_}
    local offfile="$STATE_DIR/offsets/$key"
    local size inode old_inode old_offset start
    size=$(stat -c%s -- "$log" 2>/dev/null) || return 0
    inode=$(stat -c%i -- "$log")

    old_inode=0; old_offset=0
    if [[ -f "$offfile" ]]; then
        read -r old_inode old_offset < "$offfile" || true
    fi

    if [[ "$SCAN_TYPE" == "recent" && "$inode" == "$old_inode" && "$size" -ge "$old_offset" ]]; then
        # Same file as last time and it only grew: read just the new tail.
        start=$old_offset
    else
        # Full scan, rotated file (inode changed), or truncated file:
        # read from the beginning.
        start=0
    fi

    tail -c +$((start + 1)) -- "$log"
    echo "$inode $size" > "$offfile"
}

# scan_pattern <glob> 
# Expands a glob, applies the per-service filter (same heuristics as the
# original script), extracts IPs, and appends "ip<TAB>log" lines to RAW_IPS.
# Note: NO geo lookup and NO timestamping happens here anymore - that is the
# expensive part and it is now done once per UNIQUE ip later (reason #3).
scan_pattern() {
    local pattern=$1
    local log
    for log in $pattern; do
        [[ -e "$log" ]] || continue
        echo "Processing $log..."
        case "$log" in
            *auth.log*)
                read_log "$log" | grep 'nvalid' ;;
            *dovecot.log*)
                read_log "$log" | grep -E 'error|no auth' ;;
            *exim4/mainlog*)
                read_log "$log" | grep -v 'Connection timed out' ;;
            *hestia/nginx-access.log*)
                # access log: keep requests whose status is not 2xx/5xx
                read_log "$log" | awk '($9 !~ /^"?2/ && $9 !~ /^"?5/) {print $1}' ;;
            *domains/*access*|*domains/*.log*)
                read_log "$log" | awk '($9 !~ /^"?2/ && $9 !~ /^"?5/) {print $1}' ;;
            *)
                read_log "$log" ;;
        esac | grep -Eo "$IP_REGEX" | awk -v l="$log" '{print $0 "\t" l}' >> "$RAW_IPS"
    done
}

# Which files to look at. In recent mode we list only the live files; the
# offset mechanism then ensures we read only their new bytes.
if [[ "$SCAN_TYPE" == "full" ]]; then
    LOG_PATTERNS=(
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
        "/var/log/nginx/domains/*.log*"
        "/var/log/apache2/domains/*.log*"
    )
else
    LOG_PATTERNS=(
        "/var/log/nginx/domains/*.error.log"
        "/var/log/nginx/error.log"
        "/var/log/apache2/domains/*.error.log"
        "/var/log/apache2/error.log"
        "/var/log/auth.log"
        "/var/log/dovecot.log"
        "/var/log/exim4/mainlog"
        "/var/log/exim4/rejectlog"
        "/var/log/hestia/nginx-access.log"
        "/var/log/hestia/nginx-error.log"
        "/var/log/nginx/domains/*.log"
        "/var/log/apache2/domains/*.log"
    )
fi

for pattern in "${LOG_PATTERNS[@]}"; do
    scan_pattern "$pattern"
done

# --- Failed SSH logins from btmp --------------------------------------------
# lastb reads /var/log/btmp in full, which gets huge on exposed hosts.
# Newer util-linux supports --since; use it to read only the retention window
# and fall back to a plain lastb on older systems. Also make sure btmp is in
# your logrotate config - that is the real fix for its size.
{ lastb --since "-${RETENTION_DAYS}days" 2>/dev/null || lastb; } \
    | awk '{print $3}' | grep -Eo "$IP_REGEX" \
    | awk '{print $0 "\t/var/log/btmp"}' >> "$RAW_IPS"

###############################################################################
# FILTERING: exclusions + hit threshold
###############################################################################

# Exact-match exclusion (reason #6): load excluded IPs into an awk set and
# compare the whole IP field, then apply the anchored range regex.
sort "$RAW_IPS" | uniq \
    | awk -F'\t' 'NR==FNR { skip[$1]=1; next } !($1 in skip)' "$EXCLUDE_IP_FILE" - \
    | grep -vE "$EXCLUDE_RANGES" > "$CANDIDATES"

# Hit threshold (reason #8): count how often each IP appeared across ALL logs
# this run; keep only those with >= MIN_HITS occurrences.
awk -F'\t' '{count[$1]++} END {for (ip in count) if (count[ip] >= '"$MIN_HITS"') print ip}' \
    "$RAW_IPS" | sort > "$WORKDIR/over_threshold.txt"

# An IP makes the final list if it survived the exclusions AND the threshold.
cut -f1 "$CANDIDATES" | sort -u \
    | comm -12 - "$WORKDIR/over_threshold.txt" > "$NEW_BANS"

NEW_COUNT=$(wc -l < "$NEW_BANS")
echo "Found $NEW_COUNT unique candidate IPs this run."

###############################################################################
# GEO LOOKUP - once per unique IP, with a persistent cache (reason #3)
###############################################################################

# geo_of <ip>: print cached geo info, or look it up once and cache it.
# The cache lookup is an exact match on the first tab-separated field.
geo_of() {
    local ip=$1 geo
    geo=$(awk -F'\t' -v ip="$ip" '$1 == ip {print $2; exit}' "$GEO_CACHE")
    if [[ -z "$geo" ]]; then
        geo=$(geoiplookup "$ip" 2>/dev/null | awk -F": " '{print $2; exit}')
        [[ -z "$geo" ]] && geo="unknown"
        printf '%s\t%s\n' "$ip" "$geo" >> "$GEO_CACHE"
    fi
    printf '%s' "$geo"
}

###############################################################################
# UPDATE THE ON-DISK LISTS (with retention pruning, reason #2)
###############################################################################

TSTAMP=$(date +"%Y-%m-%d | %T")
CUTOFF=$(date -d "-${RETENTION_DAYS} days" +"%Y-%m-%d")

# 1) Prune the trail: keep only lines whose date field (4th "|" field) is
#    within the retention window. YYYY-MM-DD compares correctly as a string.
awk -F'|' -v cutoff="$CUTOFF" '
    { d=$4; gsub(/^[ \t]+|[ \t]+$/, "", d); if (d >= cutoff) print }
' "$TRAIL" > "$WORKDIR/trail.pruned" || true

# 2) Append this run's findings. We only do the geo lookup for IPs we have
#    not already got in the pruned trail, to keep the loop short. All joins
#    below are EXACT matches on the IP field (no substring surprises).
awk -F'|' '{ip=$1; gsub(/[ \t]/,"",ip); print ip}' "$WORKDIR/trail.pruned" \
    | sort -u > "$WORKDIR/known_ips.txt"

# one candidate line per new IP: keep the first log it was seen in
awk -F'\t' '
    NR==FNR { want[$1]=1; next }            # NEW_BANS -> set of IPs to ban
    ($1 in want) && !seen[$1]++ { print }   # first matching candidate line
' "$NEW_BANS" "$CANDIDATES" > "$WORKDIR/new_with_log.txt"

while IFS=$'\t' read -r ip log; do
    if ! grep -qxF "$ip" "$WORKDIR/known_ips.txt"; then
        echo "$ip | $log | $(geo_of "$ip") | $TSTAMP" >> "$WORKDIR/trail.pruned"
    fi
done < "$WORKDIR/new_with_log.txt"

sort -o "$WORKDIR/trail.pruned" "$WORKDIR/trail.pruned"
cp "$WORKDIR/trail.pruned" "$TRAIL"

# 3) meinban.txt is now simply DERIVED from the pruned trail, so it shrinks
#    automatically as old entries age out - this is what stops the unbounded
#    growth you were seeing.
awk -F'|' '{gsub(/[ \t]/,"",$1); print $1}' "$TRAIL" | sort -u > "$FILE"
echo "Ban list now contains $(wc -l < "$FILE") IPs (retention ${RETENTION_DAYS}d)."

###############################################################################
# APPLY BANS VIA IPSET (reason #1 and #5)
###############################################################################

if [[ "$APPLY_BANS" == "1" ]] && command -v ipset >/dev/null 2>&1; then
    # Create the sets if missing. "timeout" gives every entry a default TTL;
    # the kernel removes expired entries on its own - no cleanup job needed.
    ipset create "$IPSET_NAME"     hash:ip  timeout "$BAN_TIMEOUT" -exist
    ipset create "$IPSET_NET_NAME" hash:net timeout "$BAN_TIMEOUT" -exist

    # Make sure exactly ONE iptables rule per set exists. -C checks for the
    # rule; -I inserts it at the top only if the check fails.
    iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null \
        || iptables -I INPUT -m set --match-set "$IPSET_NAME" src -j DROP
    iptables -C INPUT -m set --match-set "$IPSET_NET_NAME" src -j DROP 2>/dev/null \
        || iptables -I INPUT -m set --match-set "$IPSET_NET_NAME" src -j DROP

    # Subnet aggregation (reason #5): if SUBNET_THRESHOLD+ distinct IPs share
    # a /24, ban the whole /24 with a single hash:net entry.
    awk -F. '{print $1"."$2"."$3}' "$FILE" | sort | uniq -c \
        | awk -v t="$SUBNET_THRESHOLD" '$1 >= t {print $2".0/24"}' \
        > "$WORKDIR/subnets.txt"

    while read -r net; do
        ipset add "$IPSET_NET_NAME" "$net" -exist   # -exist refreshes the TTL
    done < "$WORKDIR/subnets.txt"

    # Add individual IPs, skipping ones already covered by a banned /24
    # to keep the hash:ip set as small as possible.
    while read -r ip; do
        prefix=$(echo "$ip" | awk -F. '{print $1"."$2"."$3}')
        if ! grep -q "^$prefix\.0/24$" "$WORKDIR/subnets.txt"; then
            ipset add "$IPSET_NAME" "$ip" timeout "$BAN_TIMEOUT" -exist
        fi
    done < "$FILE"

    echo "ipset: $(ipset list "$IPSET_NAME" | grep -c '^[0-9]') IPs, $(wc -l < "$WORKDIR/subnets.txt") /24 subnets banned."
    # NOTE: ipset contents do not survive a reboot. Either save/restore them
    # (ipset save > /etc/ipset.conf + a small systemd unit / netfilter-persistent),
    # or just rely on the next cron run to repopulate the set.
else
    echo "ipset not applied (APPLY_BANS=$APPLY_BANS or ipset missing)."
    echo "You can still feed $FILE to Hestia/Fail2Ban as before."
fi

echo "Done ($SCAN_TYPE scan)."
