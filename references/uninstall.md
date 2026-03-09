# ARP Uninstall & Maintenance

## Backup Before Uninstalling

```bash
# Save your identity key
cp ~/.config/arpc/key ~/.config/arpc/key.backup.$(date +%Y%m%d)
# Save contacts
cp ~/.config/arpc/contacts.toml ~/.config/arpc/contacts.toml.backup.$(date +%Y%m%d)
```

## Full Uninstall

To remove ARP completely:

```bash
# Stop daemon
if [ "$(uname -s)" = "Darwin" ]; then
    launchctl bootout gui/$(id -u)/ing.offgrid.arpc 2>/dev/null
    rm -f ~/Library/LaunchAgents/ing.offgrid.arpc.plist
fi
pkill -f "arpc start" 2>/dev/null
systemctl stop arpc 2>/dev/null          # Linux root systemd
systemctl --user stop arpc 2>/dev/null   # Linux user systemd

# Remove binary
rm -f ~/.local/bin/arpc /usr/local/bin/arpc

# Remove config and data (⚠️ This deletes your identity key!)
rm -rf ~/.config/arpc
```

## Disable Webhook Only (Keep arpc)

```bash
# Disable webhook in config (section-scoped — only touches [webhook])
awk '/^\[webhook\]/{in_section=1} in_section && /^enabled = true/{sub(/true/, "false"); in_section=0} 1' ~/.config/arpc/config.toml > ~/.config/arpc/config.toml.tmp && mv ~/.config/arpc/config.toml.tmp ~/.config/arpc/config.toml

# Restart daemon
pkill -f "arpc start" 2>/dev/null; sleep 1; arpc start &
```

## Update arpc

```bash
# Check for updates
arpc update --check

# Apply updates
arpc update

# Or just run the installer again — it will download the latest version
curl -fsSL https://arp.offgrid.ing/install.sh | bash
```
