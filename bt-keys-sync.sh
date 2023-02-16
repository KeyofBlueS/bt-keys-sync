#!/bin/bash

# bt-keys-sync

# Version:    0.1.1
# Author:     KeyofBlueS
# Repository: https://github.com/KeyofBlueS/bt-keys-sync
# License:    GNU General Public License v3.0, https://opensource.org/licenses/GPL-3.0

function bt_keys_sync() {

	if [[ -f "/tmp/SYSTEM_hive_win" ]]; then
		if ! cmp -s "${system_hive}" "/tmp/SYSTEM_hive_win"; then
			cp "${system_hive}" "/tmp/SYSTEM_hive_win"
		fi
	else
		cp "${system_hive}" "/tmp/SYSTEM_hive_win"
	fi
	echo
	echo -e "\e[1;33mIn order to proceed you must grant root permissions\e[0m"
	check_sudo
	if ! sudo bash -c "command -v reged" >/dev/null; then
		echo -e "\e[1;31mERROR: This script require \e[1;34mchntpw\e[1;31m. Use e.g. \e[1;34msudo apt install chntpw\e[0m"
		exit 1
	fi
	sudo reged -x "/tmp/SYSTEM_hive_win" "HKEY_LOCAL_MACHINE\SYSTEM" "\\${control_set}\Services\BTHPORT\Parameters\Keys" "/tmp/bt_keys.reg"

	if [[ -f "/tmp/bt_keys.reg" ]] && cat -v "/tmp/bt_keys.reg" | sed 's/\^M//g' | grep -Fq "HKEY_LOCAL_MACHINE\SYSTEM\\${control_set}\Services\BTHPORT\Parameters\Keys"; then
		#check_sudo
		bt_controllers="$(sudo ls "/var/lib/bluetooth/" | grep -o -E "([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}")"

		if [[ -z "${bt_controllers}" ]]; then
			echo -e "\e[1;31m* no bluetooth controllers found\e[0m"
			exit 1
		fi

		for bt_controller in ${bt_controllers}; do
			echo
			bt_controller_reg="$(echo "${bt_controller//:/$''}" | tr '[:upper:]' '[:lower:]')"
			echo "- bluetooth controller: ${bt_controller}"
			if cat -v "/tmp/bt_keys.reg" | sed 's/\^M//g' | grep -q "${bt_controller_reg}"; then
				#check_sudo
				bt_devices="$(sudo ls "/var/lib/bluetooth/${bt_controller}/" | grep -o -E "([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}")"
				if [[ -z "${bt_devices}" ]]; then
					echo -e "\e[1;31m* no paired bluetooth devices found\e[0m"
					exit 1
				fi

				win_controller="$(cat -v "/tmp/bt_keys.reg" | sed 's/\^M//g' | awk "/"${bt_controller_reg}"/,/^$/")"

				for bt_device in ${bt_devices}; do
					bt_device_reg="$(echo "${bt_device//:/$''}" | tr '[:upper:]' '[:lower:]')"
					#check_sudo
					bt_device_name="$(sudo cat "/var/lib/bluetooth/${bt_controller}/${bt_device}/info" | grep '^Alias=' | awk -F'=' '{print $2}')"
					if [[ -z "${bt_device_name}" ]]; then
						#check_sudo
						bt_device_name="$(sudo cat "/var/lib/bluetooth/${bt_controller}/${bt_device}/info" | grep '^Name=' | awk -F'=' '{print $2}')"
					fi
					echo "	- bluetooth device: ${bt_device} - ${bt_device_name}"
					win_key="$(echo "${win_controller}" | grep "${bt_device_reg}" | awk -F':' '{print $2}')"
					win_key="$(echo ${win_key//,/$''} | tr '[:lower:]' '[:upper:]')"
					if [[ -z "${win_key}" ]]; then
						echo "		- windows key not found"
					else
						echo "		- windows key is ${win_key}"
					fi
					#check_sudo
					linux_key="$(sudo cat "/var/lib/bluetooth/${bt_controller}/${bt_device}/info" | grep 'Key=' | awk -F'=' '{print $2}')"
					echo "		- linux key is   ${linux_key}"
					if [[ -z "${win_key}" ]]; then
						echo -e "\e[1;31m		* please pair this device in windows\e[0m"
					else
						retry='0'
						while true; do
							if [[ "${retry}" -eq '10' ]]; then
								echo -e "\e[1;31m* error while updating the key!\e[0m"
								break
							fi
							if [[ "${win_key}" != "${linux_key}" ]]; then
								updated='1'
								echo -e "\e[1;33m		* updating key...\e[0m"
								#check_sudo
								sudo sed -i "s/${linux_key}/${win_key}/g" "/var/lib/bluetooth/${bt_controller}/${bt_device}/info"
								#check_sudo
								linux_key="$(sudo cat "/var/lib/bluetooth/${bt_controller}/${bt_device}/info" | grep 'Key=' | awk -F'=' '{print $2}')"
								echo "		- linux key is   ${linux_key}"
							else
								echo -e "\e[1;32m		* ok\e[0m"
								noerror='1'
								break
							fi
							retry="$(("${retry}" + 1))"
						done
					fi
				done

				if [[ "${updated}" = '1' ]]; then
					echo
					echo -e "\e[1;32m- restarting bluetooth service...\e[0m"
					#check_sudo
					sudo systemctl restart bluetooth
				fi

			else
				echo -e "\e[1;31m* bluetooth controller not found in windows\e[0m"
			fi
		done
	else
		echo -e "\e[1;31m* ${system_hive}: error while exporting windows SYSTEM registry hive to /tmp/bt_keys.reg\e[0m"
		error='1'
	fi

}

function check_sudo() {

	while true; do
		PROCESSNAME="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 12 ; echo '')"
		timeout_sudo &
		if bash -c "exec -a du_${PROCESSNAME} sudo -v > /dev/null 2>&1"; then
			break
		else
			echo -en "\r\e[1;31mPermission denied! Press ENTER to exit or wait 5 seconds to retry\e[0m\c"
			echo
			if read -t 5 _e; then
				exit 1
			fi
		fi
	done
}

function timeout_sudo()	{

	sleep 30
	pkill -f "du_${PROCESSNAME}"
}

function givemehelp() {

	bt_keys_sync_name="$(echo "${0}" | rev | awk -F'/' '{print $1}' | rev)"
	if ! command -v "${bt_keys_sync_name}" > /dev/null; then
		bt_keys_sync_name="$(readlink -f "${0}")"
	fi
	export bt_keys_sync_name

	echo "
# bt-keys-sync

# Version:    0.1.1
# Author:     KeyofBlueS
# Repository: https://github.com/KeyofBlueS/bt-keys-sync
# License:    GNU General Public License v3.0, https://opensource.org/licenses/GPL-3.0

### DESCRIPTION
When pairing a bluetooth device to a bluetooth controller, a random key is generated in order to authenticate the connection, so e.g. in a multi boot scenario, everytime you pair a bluetooth device in a system, you'll need to pair it again in another system, because the pairing keys are thus different.
This is true for every system, whether they are linux or windows or both or wathever.

This script is intended to be used in a linux\windows multi boot scenario. It will check the local linux paired bluetooth devices and update their pairing keys with the one exported from a valid windows SYSTEM registry hive file.
Please make sure the bluetooth devices are paired in both linux and windows before running this script!

This script require \"chntpw\". Install it e.g. with:
sudo apt install chntpw

### USAGE

Mount the windows partition, then note the path to the windows SYSTEM registry hive file, should be something like:
\"<WINDOWS_MOUNTPOINT>/Windows/System32/config/SYSTEM\"

then proceed to use this script:
$ ${bt_keys_sync_name} --path \"<full/path/of/the/windows/SYSTEM/registry/hive/file>\"

example:

$ ${bt_keys_sync_name} --path \"/media/myuser/Windows/Windows/System32/config/SYSTEM\"


Options:
-p, --path <system_hive_path>    Enter the full path of the windows SYSTEM registry hive file
-c, --control-set <control_set>  Enter the control set to check. Default is 'ControlSet001'
-h, --help                       Show this help.
"
}

noerror='0'

for opt in "$@"; do
	shift
	case "$opt" in
		'--path')			set -- "$@" '-p' ;;
		'--control-set')	set -- "$@" '-c' ;;
		'--help')			set -- "$@" '-h' ;;
		*)					set -- "$@" "$opt"
	esac
done

while getopts "p:c:h" opt; do
	case ${opt} in
		p ) system_hive="${OPTARG}"
		;;
		c ) control_set="${OPTARG}"
		;;
		h ) givemehelp; exit 0
		;;
		*) givemehelp; exit 1
		;;
	esac
done

if [[ -z "${system_hive}" ]]; then
	#givemehelp
	echo -e "\e[1;31m* please enter the full path of the windows SYSTEM registry hive file\e[0m"
	error='1'
else
	if [[ -f "${system_hive}" ]]; then
		if [[ -z "${control_set}" ]]; then
			control_set='ControlSet001'
		fi
		bt_keys_sync
	else
		#givemehelp
		echo -e "\e[1;31m* ${system_hive}: windows SYSTEM registry hive file not found\e[0m"
		error='1'
	fi
fi

if [[ "${error}" = '1' ]]; then
	echo -e "\e[1;31m* make sure you entered a valid windows SYSTEM registry hive file path\e[0m"
		givemehelp
	exit 1
elif [[ "${noerror}" = '0' ]]; then
	echo
	echo -e "\e[1;33mPlease make sure the bluetooth devices are paired in both linux and windows first!\e[0m"
	exit 0
else
	exit 0
fi
