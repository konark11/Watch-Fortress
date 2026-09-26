#!/bin/bash
# Example custom scanner script: checks a handful of common ports on the
# target and emits generic JSON findings the platform's generic_parser
# understands. Real custom scripts can emit anything generic_parser
# accepts (CSV or JSON) - this is a minimal illustrative example.
TARGET="$1"
echo "["
FIRST=1
for PORT in 22 80 443; do
  if timeout 1 bash -c "cat < /dev/null > /dev/tcp/$TARGET/$PORT" 2>/dev/null; then
    if [ $FIRST -eq 0 ]; then echo ","; fi
    FIRST=0
    echo "{\"host\":\"$TARGET\",\"title\":\"Open port $PORT detected by custom script\",\"severity\":\"info\",\"port\":$PORT}"
  fi
done
echo "]"
