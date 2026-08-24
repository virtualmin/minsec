if [ $1 -eq 0 ]; then
    systemctl --no-reload disable --now minsec.service minsec-sync.timer >/dev/null 2>&1 || :
fi
