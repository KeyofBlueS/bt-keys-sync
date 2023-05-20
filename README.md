# bt-keys-sync

# Version:    0.4.0
# Author:     KeyofBlueS
# Repository: https://github.com/KeyofBlueS/bt-keys-sync
# License:    GNU General Public License v3.0, https://opensource.org/licenses/GPL-3.0

### DESCRIPTION
When pairing a bluetooth device to a bluetooth controller, a random key is generated in order to authenticate the connection, so e.g. in a multi boot scenario, only the os in wich you last paired this device has the newer working key, you'll need to pair it again in another system (then only this other system will have the newer working key).
This is true for every system, whether they are linux or windows or both or wathever.

This script is intended to be used in a linux\windows multi boot scenario. It will check for linux and windows paired bluetooth devices and, if it finds that a device pairing key isn't equal between linux\windows, it will ask which pairing key you want to use (the os in wich you last paired this device has the newer working key) so it will update the old key with the new key accordingly.

Importing the bluetooth pairing keys from windows to linux is a safe procedure.
This could not be true for the opposite, importing the bluetooth pairing keys from linux to windows is risky as it could mess with the windows registry, so the recommended procedure is to pair your bluetooth devices in linux, then boot into windows and pair them there (if yet paired, remove them first) so windows has the newer working keys, then boot into linux and run `bt-keys-sync` and always choose \"`windows key`\" when prompted \"`which pairing key you want to use?`\" (or use option `--windows-keys`).

If you, at your own risk, decide to import the bluetooth pairing keys from linux to windows `(this has been tested on windows 10 only)` a backup of the windows SYSTEM registry hive file will be created, so in case of problems you could try to restore it.

### About Bluetooth Low Energy (BLE)
Bluetooth Low Energy Device (BLE) can be detected, but key checks will be skipped.
Please take a look here: https://github.com/KeyofBlueS/bt-keys-sync/issues/13

### INSTALL
```
curl -o /tmp/bt-keys-sync.sh 'https://raw.githubusercontent.com/KeyofBlueS/bt-keys-sync/ble/bt-keys-sync.sh'
sudo mkdir -p /opt/bt-keys-sync/
sudo mv /tmp/bt-keys-sync.sh /opt/bt-keys-sync/
sudo chown root:root /opt/bt-keys-sync/bt-keys-sync.sh
sudo chmod 755 /opt/bt-keys-sync/bt-keys-sync.sh
sudo chmod +x /opt/bt-keys-sync/bt-keys-sync.sh
sudo ln -s /opt/bt-keys-sync/bt-keys-sync.sh /usr/local/bin/bt-keys-sync
```

This script require \"chntpw\". Install it e.g. with:

`sudo apt install chntpw`

### USAGE
Mount the windows partition (make sure you have read\write access to it), then run this script:

`$ bt-keys-sync`

It will search for a windows SYSTEM registry hive file in `/media` and `/mnt`.
If no windows SYSTEM registry hive file is found, then you must enter the full path (usually is something like `"<windows_mount_point>/Windows/System32/config/SYSTEM"`).

You can skip the automatic search by the option `--path`.

With the `--control-set` option you can change the control set to check. Default is ControlSet001.

```
Options:
-p, --path <system_hive_path>    Enter the full path of the windows SYSTEM registry hive file.
-c, --control-set <control_set>  Enter the control set to check. Default is 'ControlSet001'.
-l, --linux-keys                 Import bluetooth pairing keys from linux to windows without asking.
-w, --windows-keys               Import bluetooth pairing keys from windows to linux without asking.
-o, --only-list                  Only list bluetooth devices and pairing keys, don't do anything else.
-h, --help                       Show this help.
```
