#!/bin/sh
# Portable state: the two volumes are the whole system. A snapshot is an rsync of both with ClickHouse stopped
# (consistent on-disk parts). Restore onto a box prepared by setup.sh. Run as root.
#   snapshot.sh make <dest>      e.g. user@host:/backups/webcat/   or   /mnt/backup/webcat/
#   snapshot.sh restore <src>
set -eu
case ${1:-} in
make)
  systemctl stop webcat-api clickhouse-server
  rsync -a --delete --exclude 'clickhouse/tmp/' /srv/index/ "$2/index/"
  rsync -a --delete /srv/archive/ "$2/archive/"
  systemctl start clickhouse-server webcat-api
  echo "snapshot written to $2 ($(du -sh /srv/index /srv/archive | awk '{printf "%s %s ", $1, $2}'))" ;;
restore)
  systemctl stop webcat-api clickhouse-server webcat-monitor.timer
  rsync -a --delete "$2/index/" /srv/index/
  rsync -a --delete "$2/archive/" /srv/archive/
  chown -R clickhouse:clickhouse /srv/index /srv/archive
  systemctl start clickhouse-server; sleep 5; systemctl start webcat-api webcat-monitor.timer
  echo "restored; $(clickhouse-client -q 'SELECT log, entries FROM webcat.stats FINAL FORMAT TSV' | paste -sd' ')" ;;
*) echo "usage: snapshot.sh make <dest> | restore <src>"; exit 2 ;;
esac
