#!/bin/bash

WATCH="/var/www"
ALERT_EMAIL="shabbir.3s.et@gmail.com"
ALERT_FROM="hello@envytheme.com"
HOST="$(hostname -f 2>/dev/null || hostname)"
LOG="/var/log/wp-security-monitor.log"

send_alert() {
    local subject="$1"
    local body="$2"

    echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') $subject $body" >> "$LOG"

    printf '%s\n' "$body" | \
        mail -r "$ALERT_FROM" \
        -s "SECURITY ALERT [$HOST] $subject" \
        "$ALERT_EMAIL"
}

inotifywait -m -r \
    -e create,close_write,moved_to \
    --format '%e|%w%f' \
    "$WATCH" 2>/dev/null |
while IFS='|' read -r event file; do

    base="$(basename "$file")"

    if [[ "$file" =~ /\.sc_[A-Za-z0-9]+ ]] ||
       [[ "$base" == "advanced-builder-lite.php" ]] ||
       [[ "$base" == ".bt_advanced-builder-lite" ]] ||
       [[ "$base" == ".rd_advanced-builder-lite" ]] ||
       [[ "$base" == ".sd_advanced-builder-lite" ]] ||
       [[ "$base" =~ ^\.gr_.*\.php$ ]]; then

        send_alert \
          "Known malware indicator" \
          "Event: $event
File: $file
Time: $(date -u)

Known persistence indicator detected."

        continue
    fi

    if [[ "$file" == *.php ]] &&
       [[ "$file" =~ /wp-content/(uploads|cache)/ ]]; then

        send_alert \
          "PHP created in uploads/cache" \
          "Event: $event
File: $file
Time: $(date -u)

PHP in this location requires immediate review."

        continue
    fi

    if [[ "$base" == "advanced-cache.php" ||
          "$base" == "object-cache.php" ||
          "$base" == "db.php" ||
          "$base" == "wp-config.php" ||
          "$base" == ".user.ini" ]]; then

        send_alert \
          "Sensitive WordPress file changed" \
          "Event: $event
File: $file
Time: $(date -u)"

        continue
    fi

    if [[ "$file" == *.php && -f "$file" ]]; then
        if grep -qE \
          'SCV:4\.3\.24|SCOCV:4\.3\.24|SC_TH_BEGIN|SC_ADV_BEGIN|SC_DB_BEGIN|SC_DD_BEGIN|_sc_mkdir|advanced-builder-lite' \
          "$file" 2>/dev/null; then

            send_alert \
              "SC malware signature detected" \
              "Event: $event
File: $file
Time: $(date -u)"

            continue
        fi
    fi
done
=================== SCAN ===================
#!/bin/bash

ALERT_EMAIL="shabbir.3s.et@gmail.com"
ALERT_FROM="hello@envytheme.com"
HOST="$(hostname -f 2>/dev/null || hostname)"
STATE="/var/lib/wp-security-scan"
LOG="/var/log/wp-security-scan.log"

mkdir -p "$STATE"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

{
    # Exact known persistence filenames anywhere under /var/www.
    # Ignore artifacts already quarantined during incident response.
    find /var/www \
      \( -type f -o -type d \) \
      ! -path '*quarantine-*' \
      ! -path '*quarantine-*/*' \
      \( \
        -path '*/wp-content/mu-plugins/advanced-builder-lite.php' -o \
        -path '*/wp-content/plugins/advanced-builder-lite/advanced-builder-lite.php' -o \
        -name '.bt_advanced-builder-lite' -o \
        -name '.rd_advanced-builder-lite' -o \
        -name '.sd_advanced-builder-lite' -o \
        -name '.gr_*.php' -o \
        -name '.sc_*' \
      \) -print 2>/dev/null

    # PHP created/changed during the last 10 minutes.
    find /var/www -type f -name '*.php' -mmin -10 \
      ! -path '*quarantine-*' \
      ! -path '*quarantine-*/*' \
      -print0 2>/dev/null |
    while IFS= read -r -d '' f; do

        # PHP in uploads/cache is high priority.
        case "$f" in
            */wp-content/uploads/*|*/wp-content/cache/*)
                echo "$f"
                continue
                ;;
        esac

        # Scan only recently modified PHP content.
        if grep -qE \
          'SCV:4\.(3\.24|5\.3)|SCOCV:4\.(3\.24|5\.3)|SC_TH_BEGIN|SC_ADV_BEGIN|SC_DB_BEGIN|SC_DD_BEGIN|_sc_mkdir|__scf_|advanced-builder-lite|bright-conductor-dot|prime-keeper-tap|WORDPRESS_ADMIN_USER|_pre_user_id|CURLOPT_LF_TEST|SEO Links Bot Manager|Advanced LinkFlow Control|Advanced Server Response Handler' \
          "$f" 2>/dev/null; then
            echo "$f"
        fi
    done

} | sort -u > "$TMP"

if [ -s "$TMP" ]; then
    HASH="$(sha256sum "$TMP" | awk '{print $1}')"
    OLD="$(cat "$STATE/last_hash" 2>/dev/null)"

    if [ "$HASH" != "$OLD" ]; then
        {
            echo "Suspicious WordPress filesystem indicators detected."
            echo
            echo "Host: $HOST"
            echo "Time: $(date -u)"
            echo
            cat "$TMP"
        } | mail -r "$ALERT_FROM" \
            -s "SECURITY ALERT [$HOST] WordPress filesystem indicators" \
            "$ALERT_EMAIL"

        echo "$(date -u '+%F %T UTC') alert sent" >> "$LOG"
        echo "$HASH" > "$STATE/last_hash"
    fi
else
    rm -f "$STATE/last_hash"
fi
root@EnvyTheme:/var/www/html# 
