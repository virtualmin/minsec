systemd-sysusers minsec.conf >/dev/null 2>&1 || :
systemd-tmpfiles --create minsec.conf >/dev/null 2>&1 || :
systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -eq 1 ]; then
    systemctl enable minsec.service >/dev/null 2>&1 || :
    echo "minsec installed. Review /etc/minsec/minsec.toml, then: systemctl start minsec"
else
    systemctl try-restart minsec.service >/dev/null 2>&1 || :
fi
