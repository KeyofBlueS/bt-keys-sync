#!/bin/bash

# bt-keys-sync

# Version:    0.3.1
# Author:     KeyofBlueS
# Repository: https://github.com/KeyofBlueS/bt-keys-sync
# License:    GNU General Public License v3.0, https://opensource.org/licenses/GPL-3.0


function check_bt_controllers() {

	#check_sudo
	bt_controllers_linux="$(sudo ls "/var/lib/bluetooth/" | grep -Eo "^([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}$")"
	bt_controllers_windows="$(cat -v "${tmp_dir}/${tmp_reg}" | sed 's/\^M//g' | grep -F "HKEY_LOCAL_MACHINE\SYSTEM\\${control_set}\Services\BTHPORT\Parameters\Keys\\" | grep -Eo "([[:xdigit:]]){12}")"

	bt_controllers_reg="${bt_controllers_linux//:/$''}\n${bt_controllers_windows}"

	bt_controllers="$(echo -e "${bt_controllers_reg}" | tr '[:upper:]' '[:lower:]' | sort | uniq)"

	for bt_controller in ${bt_controllers}; do
		bt_controller_macaddr="$(echo ${bt_controller:0:2}:${bt_controller:2:2}:${bt_controller:4:2}:${bt_controller:6:2}:${bt_controller:8:2}:${bt_controller:10:2} | tr '[:lower:]' '[:upper:]')"
		bt_controller_linux="$(echo "${bt_controllers_linux}" | grep "${bt_controller_macaddr}")"
		bt_controller_windows="$(echo "${bt_controllers_windows}" | grep "${bt_controller}")"
		echo
		echo "- bluetooth controller: ${bt_controller_macaddr}"
		if [[ -z "${bt_controller_linux}" ]]; then
			echo -e "\e[1;31m* bluetooth controller not found in linux\e[0m"
		fi
		if [[ -z "${bt_controller_windows}" ]]; then
			echo -e "\e[1;31m* bluetooth controller not found in windows\e[0m"
		fi
		check_bt_devices
	done
}

function check_bt_devices() {

	unset bt_devices_linux
	if [[ -n "${bt_controller_linux}" ]]; then
		#check_sudo
		bt_devices_linux="$(sudo ls "/var/lib/bluetooth/${bt_controller_linux}" | grep -Eo "^([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}$")"
	fi

	unset bt_devices_windows
	if [[ -n "${bt_controller_windows}" ]]; then
		bt_devices_windows="$(cat -v "${tmp_dir}/${tmp_reg}" | sed 's/\^M//g' | awk "/"${bt_controller_windows}"/,/^$/" | awk -F'"' '{print $2}' | grep -Eo "^([[:xdigit:]]){12}$")"
	fi

	bt_devices_reg="${bt_devices_linux//:/$''}\n${bt_devices_windows}"

	bt_devices="$(echo -e "${bt_devices_reg}" | tr '[:upper:]' '[:lower:]' | sort | uniq)"

	for bt_device in ${bt_devices}; do
		bt_device_macaddr="$(echo ${bt_device:0:2}:${bt_device:2:2}:${bt_device:4:2}:${bt_device:6:2}:${bt_device:8:2}:${bt_device:10:2} | tr '[:lower:]' '[:upper:]')"
		bt_device_linux="$(echo "${bt_devices_linux}" | grep "${bt_device_macaddr}")"
		bt_device_windows="$(echo "${bt_devices_windows}" | grep "${bt_device}")"

		#check_sudo
		bt_device_info="$(sudo cat "/var/lib/bluetooth/${bt_controller_macaddr}/${bt_device_macaddr}/info" 2>/dev/null)"
		bt_device_name="$(echo "${bt_device_info}" | grep '^Alias=' | awk -F'=' '{print $2}')"
		if [[ -z "${bt_device_name}" ]]; then
			bt_device_name="$(echo "${bt_device_info}" | grep '^Name=' | awk -F'=' '{print $2}')"
		fi
		echo
		echo "	\- bluetooth device: ${bt_device_macaddr} - ${bt_device_name}"

		unset nokey
		unset key_linux
		unset key_windows
		if [[ -z "${bt_device_linux}" ]]; then
			echo -e "\e[1;31m		* bluetooth device not found in linux\e[0m"
			nokey='1'
		else
			key_linux="$(echo "${bt_device_info}" | grep 'Key=' | grep -Eo "([[:xdigit:]]){32}$")"
			if [[ -z "${key_linux}" ]]; then
				nokey='1'
				echo "		- linux key not found"
			else
				echo "		- linux  key  is ${key_linux}"
			fi
		fi
		if [[ -z "${bt_device_windows}" ]]; then
			echo -e "\e[1;31m		* bluetooth device not found in windows\e[0m"
			nokey='1'
		else
			key_windows="$(cat -v "${tmp_dir}/${tmp_reg}" | sed 's/\^M//g' | awk "/"${bt_controller_windows}"/,/^$/" | grep "${bt_device_windows}" | grep -Eo "([[:xdigit:]]{1,2},){15}[[:xdigit:]]{2}$")"
			key_windows="$(echo ${key_windows//,/$''} | tr '[:lower:]' '[:upper:]')"
			if [[ -z "${key_windows}" ]]; then
				nokey='1'
				echo "		- windows key not found"
			else
				echo "		- windows key is ${key_windows}"
			fi
		fi
		if [[ "${nokey}" = '1' ]]; then
			continue
		else
			if [[ "${key_windows}" = "${key_linux}" ]]; then
				noerror='1'
				echo -e "\e[1;32m		* keys are synced\e[0m"
			else
				if [[ "${only_list}" = 'true' ]]; then
					echo -e "\e[1;33m		* skipping this key\e[0m"
					continue
				else
					unset bt_keys_sync_from_os
					bt_keys_sync_common
					if [[ "${bt_keys_sync_from_os}" = 'windows' ]]; then
						bt_devices_sync_from_windows+="- bluetooth controller: ${bt_controller_macaddr} \ bluetooth device: ${bt_device_macaddr} - ${bt_device_name}\n"
					elif [[ "${bt_keys_sync_from_os}" = 'linux' ]]; then
						bt_devices_sync_from_linux+="- bluetooth controller: ${bt_controller_macaddr} \ bluetooth device: ${bt_device_macaddr} - ${bt_device_name}\n"
					fi
				fi
			fi
		fi
	done
}

function bt_keys_sync_common() {

	retry='0'
	while true; do
		if [[ "${skip}" = 'true' ]]; then
			unset skip
			break
		fi
		if [[ "${retry}" -eq '10' ]]; then
			echo -e "\e[1;31m		* error while updating the key!\e[0m"
			break
		fi
		if [[ "${key_windows}" != "${key_linux}" ]]; then
			if [[ "${keys_ask}" = 'true' ]]; then
				bt_keys_sync_ask
			elif [[ "${keys_from}" = 'linux' ]]; then
				bt_keys_sync_from_linux
			elif [[ "${keys_from}" = 'windows' ]]; then
				bt_keys_sync_from_windows
			fi
		else
			echo -e "\e[1;32m		* keys are synced\e[0m"
			noerror='1'
			break
		fi
		retry="$(("${retry}" + 1))"
	done
}

function bt_keys_sync_ask() {

	while true; do
		echo -e "\e[1;32m		- which pairing key you want to use? (the os in wich you last paired this device has the newer working key)\e[0m"
		echo -e "\e[1;31m		- 0) skip	1) linux key	2) windows key\e[0m"

		unset selected_key
		read -rp "		* choose> " selected_key

		if [[ ! "${selected_key}" =~ ^[[:digit:]]+$ ]] || [[ "${selected_key}" -gt '3' ]] || [[ "${selected_key}" -lt '0' ]]; then
			echo -e "\e[1;31m		Invalid choice!\e[0m"
				sleep '1'
		elif [[ "${selected_key}" -eq '0' ]]; then
			echo -e "\e[1;33m		* skipping this key\e[0m"
			skip='true'
			break
		elif [[ "${selected_key}" -eq '1' ]]; then
			if [[ "${system_hive_permission}" = 'rw' ]]; then
				bt_keys_sync_from_linux
				break
			else
				echo
				echo -e "\e[1;31m		* ${system_hive}: you don't have write permission\e[0m"
				echo -e "\e[1;31m		* you will only be able to import bluetooth pairing keys from windows to linux, not the opposite\e[0m"
				echo -e "\e[1;31m		* make sure you have read\write access\e[0m"
				echo
				sleep '1'
			fi
		elif [[ "${selected_key}" -eq '2' ]]; then
			bt_keys_sync_from_windows
			break
		fi
	done
}

function bt_keys_sync_from_windows() {

	echo -e "\e[1;33m		* updating linux key...\e[0m"
	bt_keys_sync_from_os='windows'
	keys_updated_linux='1'
	#check_sudo
	sudo sed -i "s/${key_linux}/${key_windows}/g" "/var/lib/bluetooth/${bt_controller_macaddr}/${bt_device_macaddr}/info"
	#check_sudo
	bt_device_info="$(sudo cat "/var/lib/bluetooth/${bt_controller_macaddr}/${bt_device_macaddr}/info" 2>/dev/null)"
	key_linux="$(echo "${bt_device_info}" | grep 'Key=' | grep -Eo "([[:xdigit:]]){32}$")"
	echo "		- linux  key  is ${key_linux}"
}

function bt_keys_sync_from_linux() {

	echo -e "\e[1;33m		* updating windows registry key...\e[0m"
	bt_keys_sync_from_os='linux'
	keys_updated_windows='1'
	key_linux_reg="$(echo ${key_linux:0:2},${key_linux:2:2},${key_linux:4:2},${key_linux:6:2},${key_linux:8:2},${key_linux:10:2},${key_linux:12:2},${key_linux:14:2},${key_linux:16:2},${key_linux:18:2},${key_linux:20:2},${key_linux:22:2},${key_linux:24:2},${key_linux:26:2},${key_linux:28:2},${key_linux:30:2} | tr '[:upper:]' '[:lower:]')"
	key_windows_reg="$(cat -v "${tmp_dir}/${tmp_reg}" | sed 's/\^M//g' | awk "/"${bt_controller_windows}"/,/^$/" | grep "${bt_device_windows}" | grep -Eo "([[:xdigit:]]{1,2},){15}[[:xdigit:]]{2}$")"
	#check_sudo
	sudo sed -i "s/\"${bt_device_windows}\"=hex:${key_windows_reg}/\"${bt_device_windows}\"=hex:${key_linux_reg}/g" "${tmp_dir}/${tmp_reg}"
	key_windows="$(cat -v "${tmp_dir}/${tmp_reg}" | sed 's/\^M//g' | awk "/"${bt_controller_windows}"/,/^$/" | grep "${bt_device_windows}" | grep -Eo "([[:xdigit:]]{1,2},){15}[[:xdigit:]]{2}$")"
	key_windows="$(echo ${key_windows//,/$''} | tr '[:lower:]' '[:upper:]')"
	echo "		- windows key is ${key_windows}"
}

function bt_keys_sync() {

	echo
	echo -e "\e[1;33mIn order to proceed you must grant root permissions\e[0m"
	check_sudo
	if ! sudo bash -c "command -v reged" >/dev/null; then
		echo -e "\e[1;31mERROR: This script require \e[1;34mchntpw\e[1;31m. Use e.g. \e[1;34msudo apt install chntpw\e[0m"
		exit 1
	fi

	if [[ -f "${tmp_dir}/${tmp_hive}" ]]; then
		if ! cmp -s "${system_hive}" "${tmp_dir}/${tmp_hive}"; then
			cp "${system_hive}" "${tmp_dir}/${tmp_hive}"
		fi
	else
		cp "${system_hive}" "${tmp_dir}/${tmp_hive}"
	fi

	if ! [[ -f "${tmp_dir}/${tmp_hive}" ]]; then
		echo -e "\e[1;31m* error while copying windows SYSTEM registry hive to ${tmp_dir}/${tmp_hive}\e[0m"
		exit 1
	fi

	#check_sudo
	if sudo reged -x "${tmp_dir}/${tmp_hive}" "HKEY_LOCAL_MACHINE\SYSTEM" "\\${control_set}\Services\BTHPORT\Parameters\Keys" "${tmp_dir}/${tmp_reg}"; then
		if [[ -f "${tmp_dir}/${tmp_reg}" ]] && cat -v "${tmp_dir}/${tmp_reg}" | sed 's/\^M//g' | grep -Fq "HKEY_LOCAL_MACHINE\SYSTEM\\${control_set}\Services\BTHPORT\Parameters\Keys"; then
			check_bt_controllers
			if [[ "${noerror}" != '1' ]]; then
				echo
				echo -e "\e[1;33mPlease make sure the bluetooth devices are paired in both linux and windows!\e[0m"
			fi
			if [[ "${keys_updated_linux}" = '1' ]]; then
				echo
				echo -e "\e[1;32m---------------------------------------------------------------------\e[0m"
				echo -e "\e[1;32m---------------------------------------------------------------------\e[0m"
				echo -e "\e[1;32mThe windows bluetooth pairing keys from the following devices have been imported to linux:\e[0m"
				echo -e "${bt_devices_sync_from_windows}"
				echo -e "\e[1;32mThe os in wich you last paired these devices has the newer working keys, so make sure that windows is the last os in which you paired these bluetooth devices!\e[0m"
				echo -e "\e[1;32mIf not, boot into windows and pair them there (if yet paired, remove them first), then boot into linux and run ${bt_keys_sync_name} again.\e[0m"
				echo
				echo -e "\e[1;32m- restarting bluetooth service...\e[0m"
				#check_sudo
				sudo systemctl restart bluetooth
				echo -e "\e[1;32m---------------------------------------------------------------------\e[0m"
				echo -e "\e[1;32m---------------------------------------------------------------------\e[0m"
			fi

			if [[ "${keys_updated_windows}" = '1' ]]; then
				echo
				echo -e "\e[1;31m---------------------------------------------------------------------\e[0m"
				echo -e "\e[1;31m---------------------------------------------------------------------\e[0m"
				echo -e "\e[1;31mThe linux bluetooth pairing keys from the following devices haven't yet been imported to the windows SYSTEM registry hive:\e[0m"
				echo -e "${bt_devices_sync_from_linux}"
				echo -e "\e[1;31mThis procedure is risky as it could mess with the windows registry.\e[0m"
				echo -e "\e[1;31mThe os in wich you last paired these devices has the newer working keys, so the recommended procedure is to boot into windows and pair them there (if yet paired, remove them first) so windows has the newer working keys, then boot into linux and run ${bt_keys_sync_name} and always choose \"windows key\" when prompted \"which pairing key you want to use?\" (or use option --windows-keys).\e[0m"
				echo -e "\e[1;31mIf you, at your own risk, decide to import the bluetooth pairing keys from linux to windows (this has been tested on windows 10 only) a backup of the windows SYSTEM registry hive file will be created, so in case of problems you could try to restore it.\e[0m"
				while true; do
					echo
					echo -e "\e[1;31m- do you want to import the linux bluetooth pairing keys to the windows SYSTEM registry hive?\e[0m"
					echo -e "\e[1;32m0) No\e[0m"
					echo -e "\e[1;31m1) Yes\e[0m"
					read -p " choose> " import_registry
					if [[ ! "${import_registry}" =~ ^[[:digit:]]+$ ]] || [[ "${import_registry}" -gt '1' ]] || [[ "${import_registry}" -lt 0 ]]; then
						echo -e "\e[1;31mInvalid choice!\e[0m"
						sleep '1'
					elif [[ "${import_registry}" -eq '0' ]]; then
						echo -e "\e[1;33mwindows SYSTEM registry hive left untouched.\e[0m"
						echo -e "\e[1;33mwindows bluetooth pairing keys haven't been updated.\e[0m"
						exit 0
					elif [[ "${import_registry}" -eq '1' ]]; then
						backup_date="$(date +%F_%H-%M-%S)"
						echo
						echo -e "\e[1;31m- making a windows SYSTEM registry hive file backup at:\e[0m"
						echo "${system_hive}_${backup_date}.bak"
						cp "${system_hive}" "${system_hive}_${backup_date}.bak"
						if [[ -f "${system_hive}_${backup_date}.bak" ]]; then
							echo
							echo -e "\e[1;31m- importing the linux bluetooth pairing keys to the windows SYSTEM registry hive...\e[0m"
							#check_sudo
							sudo reged -ICN "${tmp_dir}/${tmp_hive}" "HKEY_LOCAL_MACHINE\SYSTEM" "${tmp_dir}/${tmp_reg}"
							cp "${tmp_dir}/${tmp_hive}" "${system_hive}"
							break
						else
							echo -e "\e[1;31m- error while making the backup of the windows SYSTEM registry hive file\e[0m"
							echo -e "\e[1;31m- aborting\e[0m"
							exit 1
						fi
					fi
				done
				echo -e "\e[1;31m---------------------------------------------------------------------\e[0m"
				echo -e "\e[1;31m---------------------------------------------------------------------\e[0m"
			fi
		else
			echo -e "\e[1;31m* ${system_hive}: error while exporting windows SYSTEM registry hive to ${tmp_dir}/${tmp_reg}\e[0m"
			error='1'
		fi
	else
		echo -e "\e[1;31m* ${system_hive}: error while exporting windows SYSTEM registry hive to ${tmp_dir}/${tmp_reg}\e[0m"
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
			if read -t '5' _e; then
				exit 1
			fi
		fi
	done
}

function timeout_sudo()	{

	sleep '30'
	pkill -f "du_${PROCESSNAME}"
}

function find_system_hive()	{

	for search_path in '/media/' '/mnt/'; do
		echo -e "\e[1;32m* searching in ${search_path} ...\e[0m"
		system_hive_find="$(find "${search_path}" -type f -ipath '*/Windows/System32/config/*' -iname 'SYSTEM' 2>/dev/null)"
		if [[ -n "${system_hive_find}" ]]; then
			if [[ -z "${system_hive_found}" ]]; then
				system_hive_found="${system_hive_find}"
			else
				system_hive_found+="/n${system_hive_find}"
			fi
		fi
	done

	while true; do
		#clear		
		echo
		if [[ -z "${system_hive_found}" ]]; then
			echo -e "\e[1;31m- no results while searching for a windows SYSTEM registry hive file\e[0m"
			while true; do
				echo -e "\e[1;32m* please enter the full path of the windows SYSTEM registry hive file:\e[0m"
				echo ' 0) Exit'
				read -p " > " system_hive
				if echo "${system_hive}" | grep -Eixq "(exit|e|quit|q|0)"; then
					exit 0
				else
					if [[ -f "${system_hive}" ]]; then
						break 2
					else
						echo -e "\e[1;31m* ${system_hive}: file not found\e[0m"
						echo
						sleep '2'
					fi
				fi
			done
		else
			echo -e "\e[1;32m* please select a windows SYSTEM registry hive file:\e[0m"
		fi
		local i='0'
		echo ' 0) Exit'
		while IFS=, read -r exp_path; do
			if [[ -n "${exp_path}" ]]; then
				i=$((i + 1))
				sp1=' '
				if [[ "${i}" -gt '9' ]]; then
					unset sp1
				fi
				path=${exp_path}
				echo -e "${sp1}${i}) ${path}"
			fi
		done <<< "${system_hive_found}"
		unset selected_path
		echo
		read -rp " choose> " selected_path
		if [[ ! "${selected_path}" =~ ^[[:digit:]]+$ ]] || [[ "${selected_path}" -gt "${i}" ]] || [[ "${selected_path}" -lt '0' ]]; then
			echo
			echo -e "\e[1;31mInvalid choice!\e[0m"
				sleep '1'
		elif [[ "${selected_path}" -eq '0' ]]; then
			exit 0
		else
			system_hive="$(echo "${system_hive_found}" | sed -n "${selected_path}"p)"
			break
		fi
	done
}

function check_keys_from()	{

	if [[ -n "${keys_from}" ]]; then
		echo -e "\e[1;31m* ERROR: only one option is permitted between --linux-keys and --windows-keys\e[0m"
		givemehelp
		exit 1
	else
		keys_from="${keys_from_check}"
		unset keys_ask
	fi
}

function givemehelp() {

	echo "
# bt-keys-sync

# Version:    0.3.1
# Author:     KeyofBlueS
# Repository: https://github.com/KeyofBlueS/bt-keys-sync
# License:    GNU General Public License v3.0, https://opensource.org/licenses/GPL-3.0

### DESCRIPTION
When pairing a bluetooth device to a bluetooth controller, a random key is generated in order to authenticate the connection, so e.g. in a multi boot scenario, only the os in wich you last paired this device has the newer working key, you'll need to pair it again in another system (then only this other system will have the newer working key).
This is true for every system, whether they are linux or windows or both or wathever.

This script is intended to be used in a linux\windows multi boot scenario. It will check for linux and windows paired bluetooth devices and, if it finds that a device pairing key isn't equal between linux\windows, it will ask which pairing key you want to use (the os in wich you last paired this device has the newer working key) so it will update the old key with the new key accordingly.

Importing the bluetooth pairing keys from windows to linux is a safe procedure.
This could not be true for the opposite, importing the bluetooth pairing keys from linux to windows is risky as it could mess with the windows registry, so the recommended procedure is to pair your bluetooth devices in linux, then boot into windows and pair them there (if yet paired, remove them first) so windows has the newer working keys, then boot into linux and run ${bt_keys_sync_name} and always choose \"windows key\" when prompted \"which pairing key you want to use?\" (or use option --windows-keys).
If you, at your own risk, decide to import the bluetooth pairing keys from linux to windows (this has been tested on windows 10 only) a backup of the windows SYSTEM registry hive file will be created, so in case of problems you could try to restore it.

This script require \"chntpw\". Install it e.g. with:
sudo apt install chntpw

### USAGE
Mount the windows partition (make sure you have read\write access to it), then run this script:
$ ${bt_keys_sync_name}

It will search for a windows SYSTEM registry hive file in /media and /mnt.
If no windows SYSTEM registry hive file is found, then you must enter the full path (usually is something like \"<windows_mount_point>/Windows/System32/config/SYSTEM\").

You can skip the automatic search by the option --path.

With the --control-set option you can change the control set to check. Default is ControlSet001.

Options:
-p, --path <system_hive_path>    Enter the full path of the windows SYSTEM registry hive file.
-c, --control-set <control_set>  Enter the control set to check. Default is 'ControlSet001'.
-l, --linux-keys                 Import bluetooth pairing keys from linux to windows without asking.
-w, --windows-keys               Import bluetooth pairing keys from windows to linux without asking.
-s, --only-list                  Only list bluetooth devices and pairing keys, don't do anything else.
-h, --help                       Show this help.
"
}

bt_keys_sync_name="$(echo "${0}" | rev | awk -F'/' '{print $1}' | rev)"
if ! command -v "${bt_keys_sync_name}" > /dev/null; then
	bt_keys_sync_name="$(readlink -f "${0}")"
fi
export bt_keys_sync_name

tmp_dir='/tmp'
tmp_reg='bt_keys.reg'
tmp_hive='SYSTEM_hive_win'
control_set='ControlSet001'
keys_ask='true'

for opt in "$@"; do
	shift
	case "$opt" in
		'--path')			set -- "$@" '-p' ;;
		'--control-set')	set -- "$@" '-c' ;;
		'--linux-keys')		set -- "$@" '-l' ;;
		'--windows-keys')	set -- "$@" '-w' ;;
		'--only-list')	    set -- "$@" '-o' ;;
		'--help')			set -- "$@" '-h' ;;
		*)					set -- "$@" "$opt"
	esac
done

while getopts "p:c:lwoh" opt; do
	case ${opt} in
		p ) system_hive="${OPTARG}"
		;;
		c ) control_set="${OPTARG}"
		;;
		l ) keys_from_check='linux'; check_keys_from
		;;
		w ) keys_from_check='windows'; check_keys_from
		;;
		o ) only_list='true'
		;;
		h ) givemehelp; exit 0
		;;
		*) givemehelp; exit 1
		;;
	esac
done

if [[ -z "${system_hive}" ]] || ! [[ -f "${system_hive}" ]]; then
	find_system_hive
fi

if [[ -f "${system_hive}" ]]; then
	if [[ -r "${system_hive}" ]]; then
		system_hive_permission='r'
	else
		echo -e "\e[1;31m* ${system_hive}: you don't have read permission\e[0m"
		exit 1
	fi
	if [[ -w "${system_hive}" ]]; then
		system_hive_permission+="w"
	else
		echo -e "\e[1;31m* ${system_hive}: you don't have write permission\e[0m"
		echo -e "\e[1;31m* you will only be able to import bluetooth pairing keys from windows to linux, not the opposite\e[0m"
		if [[ "${keys_from}" = 'linux' ]]; then
			echo -e "\e[1;31m* make sure you have read\write access\e[0m"
			exit 1
		fi
	fi
	bt_keys_sync
else
	echo -e "\e[1;31m* ${system_hive}: file not found\e[0m"
	error='1'
fi

if [[ "${error}" = '1' ]]; then
	echo -e "\e[1;31m* make sure you enter a valid windows SYSTEM registry hive file path\e[0m"
	if [[ "${control_set}" != 'ControlSet001' ]]; then
		echo -e "\e[1;31m* make sure you enter a valid control set\e[0m"
	fi
	givemehelp
	exit 1
fi

exit 0
