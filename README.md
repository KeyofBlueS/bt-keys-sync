# bt-keys-sync

# Version:    0.1.3
# Author:     KeyofBlueS
# Repository: https://github.com/KeyofBlueS/bt-keys-sync
# License:    GNU General Public License v3.0, https://opensource.org/licenses/GPL-3.0

### DESCRIPTION
When pairing a bluetooth device to a bluetooth controller, a random key is generated in order to authenticate the connection, so e.g. in a multi boot scenario, everytime you pair a bluetooth device in a system, you'll need to pair it again in another system, because the pairing keys are thus different.
This is true for every system, whether they are linux or windows or both or wathever.

This script is intended to be used in a linux\windows multi boot scenario. It will check the local linux paired bluetooth devices and update their pairing keys with the one exported from a valid windows SYSTEM registry hive file.

This script require \"chntpw\". Install it e.g. with:
`sudo apt install chntpw`

### INSTALL
```
curl -o /tmp/bt-keys-sync.sh 'https://raw.githubusercontent.com/KeyofBlueS/bt-keys-sync/master/bt-keys-sync.sh'
sudo mkdir -p /opt/bt-keys-sync/
sudo mv /tmp/bt-keys-sync.sh /opt/bt-keys-sync/
sudo chown root:root /opt/bt-keys-sync/bt-keys-sync.sh
sudo chmod 755 /opt/bt-keys-sync/bt-keys-sync.sh
sudo chmod +x /opt/bt-keys-sync/bt-keys-sync.sh
sudo ln -s /opt/bt-keys-sync/bt-keys-sync.sh /usr/local/bin/bt-keys-sync
```

### USAGE
Before running this script, please make sure the bluetooth devices are paired in both linux and windows and that windows is, in order, the last os in which you paired your bluetooth devices!
Else, if not yet, pair the bluetooth devices in linux, then boot into windows and pair them there (if yet paired, remove them first), then boot into linux and proceed.

Mount the windows partition, then note the path to the windows SYSTEM registry hive file, should be something like:
\"<WINDOWS_MOUNTPOINT>/Windows/System32/config/SYSTEM\"

The '--search' option will search for a windows SYSTEM registry hive file in /media and /mnt and if it finds a possible candidate, it will give you the path that you can use with the '--path' mandatory option.

example:

`$ bt-keys-sync --path "/media/myuser/Windows/Windows/System32/config/SYSTEM"`

With the '--control-set' option you can change the default 'ControlSet001' control set to check.

example:

`$ bt-keys-sync --control-set ControlSet002 --path "/media/myuser/Windows/Windows/System32/config/SYSTEM"`

```
Options:
-p, --path <system_hive_path>    Enter the full path of the windows SYSTEM registry hive file. Mandatory.
-c, --control-set <control_set>  Enter the control set to check. Default is 'ControlSet001'
-s, --search                     Search for a windows SYSTEM registry hive file in /media and /mnt
-h, --help                       Show this help.
```
