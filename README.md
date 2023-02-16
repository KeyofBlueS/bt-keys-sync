# bt-keys-sync

# Version:    0.1.2
# Author:     KeyofBlueS
# Repository: https://github.com/KeyofBlueS/bt-keys-sync
# License:    GNU General Public License v3.0, https://opensource.org/licenses/GPL-3.0

### DESCRIPTION
When pairing a bluetooth device to a bluetooth controller, a random key is generated in order to authenticate the connection, so e.g. in a multi boot scenario, everytime you pair a bluetooth device in a system, you'll need to pair it again in another system, because the pairing keys are thus different.
This is true for every system, whether they are linux or windows or both or wathever.

This script is intended to be used in a linux\windows multi boot scenario. It will check the local linux paired bluetooth devices and update their pairing keys with the one exported from a valid windows SYSTEM registry hive file.
Please make sure the bluetooth devices are paired in both linux and windows before running this script!

This script require "chntpw". Install it e.g. with:
```sh
sudo apt install chntpw
```
### INSTALL
```sh
curl -o /tmp/bt-keys-sync.sh 'https://raw.githubusercontent.com/KeyofBlueS/bt-keys-sync/master/bt-keys-sync.sh'
sudo mkdir -p /opt/bt-keys-sync/
sudo mv /tmp/bt-keys-sync.sh /opt/bt-keys-sync/
sudo chown root:root /opt/bt-keys-sync/bt-keys-sync.sh
sudo chmod 755 /opt/bt-keys-sync/bt-keys-sync.sh
sudo chmod +x /opt/bt-keys-sync/bt-keys-sync.sh
sudo ln -s /opt/bt-keys-sync/bt-keys-sync.sh /usr/local/bin/bt-keys-sync
```

### USAGE
Mount the windows partition, then note the path to the windows SYSTEM registry hive file, should be something like:
\"<WINDOWS_MOUNTPOINT>/Windows/System32/config/SYSTEM\"

then proceed to use this script:
```sh
$ bt-keys-sync --path "<full/path/of/the/windows/SYSTEM/registry/hive/file>"
```
example:
```sh
$ bt-keys-sync --path "/media/myuser/Windows/Windows/System32/config/SYSTEM"
```
```
Options:
-p, --path <system_hive_path>    Enter the full path of the windows SYSTEM registry hive file
-c, --control-set <control_set>  Enter the control set to check. Default is 'ControlSet001'
-h, --help                       Show this help.
```
