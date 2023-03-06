#!/bin/bash

# bt-keys-sync

# Version:    0.3.10
# Author:     KeyofBlueS
# Repository: https://github.com/KeyofBlueS/bt-keys-sync
# License:    GNU General Public License v3.0, https://opensource.org/licenses/GPL-3.0


function check_bt_controllers() {
	check_sudo
	bt_controllers_linux="$(sudo ls "/var/lib/bluetooth/" | grep -Eo "^([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}$")"
	bt_controllers_windows="$(cat -v "${tmp_dir}/${tmp_reg}" | sed 's/\^M//g' | grep -F "HKEY_LOCAL_MACHINE\SYSTEM\\${control_set}\Services\BTHPORT\Parameters\Keys" | awk -F'\' '{print $8}' | grep -Eo "([[:xdigit:]]){12}")"

	bt_controllers_reg="${bt_controllers_linux//:/$''}\n${bt_controllers_windows}"

	bt_controllers="$(echo -e "${bt_controllers_reg,,}" | sort -u)"

	for bt_controller in ${bt_controllers}; do
		bt_controller_macaddr="$(echo "${bt_controller^^}" | sed 's/.\{2\}/&:/g' | sed 's/.$//')"
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
		check_sudo
		bt_devices_linux="$(sudo ls "/var/lib/bluetooth/${bt_controller_linux}" | grep -Eo "^([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}$")"
	fi

	unset bt_devices_windows
	if [[ -n "${bt_controller_windows}" ]]; then
		bt_devices_windows="$(cat -v "${tmp_dir}/${tmp_reg}" | sed 's/\^M//g' | awk "/"${bt_controller_windows}]"/,/^$/" 2>/dev/null | awk -F'"' '{print $2}' | grep -Eo "^([[:xdigit:]]){12}$")\n"
		bt_devices_windows+="$(cat -v "${tmp_dir}/${tmp_reg}" | sed 's/\^M//g' | grep -F "HKEY_LOCAL_MACHINE\SYSTEM\\${control_set}\Services\BTHPORT\Parameters\Keys\\${bt_controller_windows}" | awk -F'\' '{print $9}' | grep -Eo "([[:xdigit:]]){12}")"
		bt_devices_windows="$(echo -e "${bt_devices_windows}")"
	fi

	bt_devices_reg="${bt_devices_linux//:/$''}\n${bt_devices_windows}"

	bt_devices="$(echo -e "${bt_devices_reg,,}" | sort -u)"

	for bt_device in ${bt_devices}; do
		bt_device_macaddr="$(echo "${bt_device^^}" | sed 's/.\{2\}/&:/g' | sed 's/.$//')"
		bt_device_linux="$(echo "${bt_devices_linux}" | grep "${bt_device_macaddr}")"
		bt_device_windows="$(echo "${bt_devices_windows}" | grep "${bt_device}")"

		if [[ -n "${bt_device_linux}" ]]; then
			check_sudo
			bt_device_info="$(sudo cat "/var/lib/bluetooth/${bt_controller_macaddr}/${bt_device_macaddr}/info" 2>/dev/null)"
			bt_device_name="$(echo "${bt_device_info}" | grep '^Alias=' | awk -F'=' '{print $2}')"
			if [[ -z "${bt_device_name}" ]]; then
				bt_device_name="$(echo "${bt_device_info}" | grep '^Name=' | awk -F'=' '{print $2}')"
			fi
			if [[ -z "${bt_device_name}" ]]; then
				bt_device_name='UNKWNOWN'
			fi
		elif [[ -n "${bt_device_windows}" ]]; then
			if [[ "${tmp_devs_deployed}" != 'true' ]]; then
				tmp_devs_deployed='true'
				check_sudo
				sudo reged -x "${tmp_dir}/${tmp_hive}" "HKEY_LOCAL_MACHINE\SYSTEM" "\\${control_set}\Services\BTHPORT\Parameters\Devices" "${tmp_dir}/${tmp_devs}" 2>&1>/dev/null
				bt_devices_info_devs_reg="$(cat -v "${tmp_dir}/${tmp_devs}" | sed 's/\^M//g')"
			fi
			bt_device_info_devs_reg="$(echo "${bt_devices_info_devs_reg}" | awk "/"${bt_device_windows}]"/,/^$/")"
			bt_device_name="$(echo "${bt_device_info_devs_reg}" | grep -F '"FriendlyName"=' | grep -Eo "([[:xdigit:]]{1,2},)+[[:xdigit:]]{2}$")"
			if [[ -z "${bt_device_name}" ]]; then
				bt_device_name="$(echo "${bt_device_info_devs_reg}" | grep -F '"Name"=' | grep -Eo "([[:xdigit:]]{1,2},)+[[:xdigit:]]{2}$")"
			fi
			if [[ -n "${bt_device_name}" ]]; then
				until [[ "${bt_device_name:(-3)}" != ',00' ]]; do
					bt_device_name="${bt_device_name::-3}"
				done
				bt_device_name="$(echo -e "\x${bt_device_name//,/$'\x'}")"
			else
				bt_device_name='UNKWNOWN'
			fi
		fi
		echo
		echo "	\- bluetooth device: ${bt_device_macaddr} - ${bt_device_name}"

		unset bt_device_type_linux
		unset key_lk_linux
		unset key_irk_linux
		unset key_lsk_linux
		unset key_ltk_linux
		unset key_ediv_linux
		unset key_rand_linux
		unset key_lk_linux_reg
		unset key_irk_linux_reg
		unset key_lsk_linux_reg
		unset key_ltk_linux_reg
		unset key_ediv_linux_reg
		unset key_rand_linux_reg
		unset bt_device_type_windows
		unset key_lk_windows
		unset key_irk_windows
		unset key_lsk_windows
		unset key_ltk_windows
		unset key_ediv_windows
		unset key_rand_windows
		unset key_lk_windows_reg
		unset key_irk_windows_reg
		unset key_lsk_windows_reg
		unset key_ltk_windows_reg
		unset key_ediv_windows_reg
		unset key_rand_windows_reg
		unset nokey
		unset bt_device_type
		if [[ -z "${bt_device_linux}" ]]; then
			echo -e "\e[1;31m		* bluetooth device not found in linux. Please pair this device in linux.\e[0m"
			nokey='1'
		else
			check_bt_device_type_linux
			if [[ "${bt_device_type_linux}" = 'standard' ]]; then # delete after BLE support will be implemented
				get_bt_keys_linux
			fi # delete after BLE support will be implemented
		fi
		if [[ -z "${bt_device_windows}" ]]; then
			echo -e "\e[1;31m		* bluetooth device not found in windows. Please pair this device in windows.\e[0m"
			nokey='1'
		else
			check_bt_device_type_windows
			if [[ "${bt_device_type_windows}" = 'standard' ]]; then
				bt_device_info_keys_reg="$(cat -v "${tmp_dir}/${tmp_reg}" | sed 's/\^M//g' | awk "/"${bt_controller_windows}]"/,/^$/" | grep "${bt_device_windows}" | grep -Eo "([[:xdigit:]]{1,2},){15}[[:xdigit:]]{2}$")"
			elif [[ "${bt_device_type_windows}" = 'ble' ]]; then
				bt_device_info_keys_reg="$(cat -v "${tmp_dir}/${tmp_reg}" | sed 's/\^M//g' | awk "/"${bt_device_windows}]"/,/^$/")"
			fi
			if [[ "${bt_device_type_windows}" = 'standard' ]]; then # delete after BLE support will be implemented
				get_bt_keys_windows
			fi # delete after BLE support will be implemented
		fi
		if [[ "${bt_device_type_linux}" = 'standard' ]] && [[ "${bt_device_type_windows}" = 'standard' ]]; then
			bt_device_type='standard'
		elif [[ "${bt_device_type_linux}" = 'ble' ]] && [[ "${bt_device_type_windows}" = 'ble' ]]; then
			bt_device_type='ble'
		elif [[ "${bt_device_type_linux}" = 'standard' ]] && [[ "${bt_device_type_windows}" = 'ble' ]] || [[ "${bt_device_type_linux}" = 'ble' ]] && [[ "${bt_device_type_windows}" = 'standard' ]]; then
			echo -e "\e[1;31m		* error: mismatch between device type!\e[0m"
			continue
		fi
		##############################################################
		# delete after BLE support will be implemented
		if [[ "${bt_device_type_linux}" = 'ble' ]] || [[ "${bt_device_type_windows}" = 'ble' ]]; then
			echo -e "\e[1;31m		* this device appear to be a Bluetooth Low Energy Device (BLE)\e[0m"
			echo -e "\e[1;31m		* support for Bluetooth Low Energy Devices is currently unimplemented\e[0m"
			echo -e "\e[1;31m		* please take a look at: \e[1;34mhttps://github.com/KeyofBlueS/bt-keys-sync/issues/13\e[0m"
			continue
		fi
		##############################################################
		if [[ "${nokey}" = '1' ]]; then
			nokey_warn='1'
			continue
		else
			compare_bt_keys
			if [[ "${different}" != 'true' ]]; then
				noerror='1'
				echo -e "\e[1;32m		* keys are synced\e[0m"
			else
				bt_keys_sync_common
			fi
		fi
	done
}

function check_bt_device_type_linux() {

	unset bt_device_type_linux
	if echo "${bt_device_info}" | grep -Eq "^\[LinkKey\]$"; then
		bt_device_type_linux='standard'
	elif [[ "$(echo "${bt_device_info}" | grep -E "^(\[IdentityResolvingKey\]|\[LocalSignatureKey\]|\[LongTermKey\]|EncSize|EDiv|Rand)" | wc -l)" -ge '5' ]]; then
		bt_device_type_linux='ble'
	fi
}

function check_bt_device_type_windows() {

	unset bt_device_type_windows
	bt_device_info_keys_reg="$(cat -v "${tmp_dir}/${tmp_reg}" | sed 's/\^M//g' | awk "/"${bt_device_windows}]"/,/^$/")"
	if [[ "$(echo "${bt_device_info_keys_reg}" | grep -E "^(\"IRK\"|\"CSRK\"|\"LTK\"|\"KeyLength\"|\"EDIV\"|\"ERand\")" | wc -l)" -ge '5' ]]; then
		bt_device_type_windows='ble'
	else
		bt_device_type_windows='standard'
	fi
}

function get_bt_keys_linux() {

	if [[ "${bt_device_type_linux}" = 'standard' ]]; then
		key_lk_linux="$(echo "${bt_device_info}" | grep '^Key=' | grep -Eo "([[:xdigit:]]){32}$")"
		if [[ -z "${key_lk_linux}" ]]; then
			nokey='1'
			echo -e "\e[1;31m		* linux   LK   key not found. Please try to remove and pair again this device in linux.\e[0m"
		else
			echo "		- linux   LK   key is ${key_lk_linux}"
		fi
	elif [[ "${bt_device_type_linux}" = 'ble' ]]; then
		key_irk_linux="$(echo "${bt_device_info}" | awk "/"\\[IdentityResolvingKey\\]"/,/^$/" | grep '^Key=' | grep -Eo "([[:xdigit:]]){32}$")" # to review
		key_lsk_linux="$(echo "${bt_device_info}" | awk "/"\\[LocalSignatureKey\\]"/,/^$/" | grep '^Key=' | grep -Eo "([[:xdigit:]]){32}$")" # to review
		key_ltk_linux="$(echo "${bt_device_info}" | awk "/"\\[LongTermKey\\]"/,/^$/" | grep '^Key=' | grep -Eo "([[:xdigit:]]){32}$")" # to review
		key_es_linux="$(echo "${bt_device_info}" | awk "/"\\[LongTermKey\\]"/,/^$/" | grep '^EncSize=' | grep -Eo "([[:digit:]])+$")" # to review
		key_ediv_linux="$(echo "${bt_device_info}" | awk "/"\\[LongTermKey\\]"/,/^$/" | grep '^EDiv=' | grep -Eo "([[:digit:]])+$")" # to review
		key_rand_linux="$(echo "${bt_device_info}" | awk "/"\\[LongTermKey\\]"/,/^$/" | grep '^Rand=' | grep -Eo "([[:digit:]])+$")" # to review
		if [[ -z "${key_irk_linux}" ]]; then
			nokey='1'
			echo -e "\e[1;31m		* linux   IRK  key not found. Please try to remove and pair again this device in linux.\e[0m"
		else
			echo -e "\e[0;32m		- linux   IRK  key is \e[0;32m${key_irk_linux}\e[0m"
		fi
		if [[ -z "${key_lsk_linux}" ]]; then
			nokey='1'
			echo -e "\e[1;31m		* linux   LSK  key not found. Please try to remove and pair again this device in linux.\e[0m"
		else
			echo -e "\e[0;32m		- linux   LSK  key is \e[0;33m${key_lsk_linux}\e[0m"
		fi
		if [[ -z "${key_ltk_linux}" ]]; then
			nokey='1'
			echo -e "\e[1;31m		* linux   LTK  key not found. Please try to remove and pair again this device in linux.\e[0m"
		else
			echo -e "\e[0;32m		- linux   LTK  key is \e[1;34m${key_ltk_linux}\e[0m"
		fi
		if [[ -z "${key_es_linux}" ]]; then
			nokey='1'
			echo -e "\e[1;31m		* linux   ES   key not found. Please try to remove and pair again this device in linux.\e[0m"
		else
			echo -e "\e[0;32m		- linux   ES   key is \e[1;35m${key_es_linux}\e[0m"
		fi
		if [[ -z "${key_ediv_linux}" ]]; then
			nokey='1'
			echo -e "\e[1;31m		* linux   EDIV key not found. Please try to remove and pair again this device in linux.\e[0m"
		else
			echo -e "\e[0;32m		- linux   EDIV key is \e[1;35m${key_ediv_linux}\e[0m"
		fi
		if [[ -z "${key_rand_linux}" ]]; then
			nokey='1'
			echo -e "\e[1;31m		* linux   RAND key not found. Please try to remove and pair again this device in linux.\e[0m"
		else
			echo -e "\e[0;32m		- linux   RAND key is \e[1;36m${key_rand_linux}\e[0m"
		fi
	fi
}

function get_bt_keys_windows() {

	if [[ "${bt_device_type_windows}" = 'standard' ]]; then
		key_lk_windows_reg="${bt_device_info_keys_reg}"
		key_lk_windows="$(echo ${key_lk_windows_reg//,/$''} | tr '[:lower:]' '[:upper:]')"
		if [[ -z "${key_lk_windows}" ]]; then
			nokey='1'
			echo -e "\e[1;31m		* windows LK   key not found. Please try to remove and pair again this device in windows.\e[0m"
		else
			echo "		- windows LK   key is ${key_lk_windows}"
		fi
	elif [[ "${bt_device_type_windows}" = 'ble' ]]; then
		key_irk_windows_reg="$(echo "${bt_device_info_keys_reg}" | grep '^"IRK"' | grep -Eo "([[:xdigit:]]{1,2},){15}[[:xdigit:]]{2}$")" # to review
		key_irk_windows="$(echo ${key_irk_windows_reg//,/$''} | tr '[:lower:]' '[:upper:]')" # to review

		key_lsk_windows_reg="$(echo "${bt_device_info_keys_reg}" | grep '^"CSRK"' | grep -Eo "([[:xdigit:]]{1,2},){15}[[:xdigit:]]{2}$")" # to review
		key_lsk_windows="$(echo ${key_lsk_windows_reg//,/$''} | tr '[:lower:]' '[:upper:]')" # to review

		key_ltk_windows_reg="$(echo "${bt_device_info_keys_reg}" | grep '^"LTK"' | grep -Eo "([[:xdigit:]]{1,2},){15}[[:xdigit:]]{2}$")" # to review
		key_ltk_windows="$(echo ${key_ltk_windows_reg//,/$''} | tr '[:lower:]' '[:upper:]')" # to review

		key_es_windows_reg="$(echo "${bt_device_info_keys_reg}" | grep '^"KeyLength"' | awk -F':' '{print $2}')" # to review
		key_es_windows="$(echo "obase=10; ibase=16; ${key_es_windows_reg}" | bc)" # to review

		key_ediv_windows_reg="$(echo "${bt_device_info_keys_reg}" | grep '^"EDIV"' | awk -F':' '{print $2}')" # to review
		key_ediv_windows="$(echo "obase=10; ibase=16; ${key_ediv_windows_reg}" | bc)" # to review

		key_rand_windows_reg="$(echo "${bt_device_info_keys_reg}" | grep '^"ERand"' | awk -F':' '{print $2}')" # to review
		key_rand_windows="$(echo "${key_rand_windows_reg}" | awk -F',' '{ for (i=NF; i>1; i--) printf("%s ",$i); print $1; }' | tr '[:lower:]' '[:upper:]')" # to review
		key_rand_windows="$(echo "obase=10; ibase=16; ${key_rand_windows//' '/$''}" | bc)" # to review

		if [[ -z "${key_irk_windows}" ]]; then
			nokey='1'
			echo -e "\e[1;31m		* windows IRK  key not found. Please try to remove and pair again this device in windows.\e[0m"
		else
			echo -e "\e[0;32m		- windows IRK  key is \e[0;32m${key_irk_windows}\e[0m"
		fi
		if [[ -z "${key_lsk_windows}" ]]; then
			nokey='1'
			echo -e "\e[1;31m		* windows LSK  key not found. Please try to remove and pair again this device in windows.\e[0m"
		else
			echo -e "\e[0;32m		- windows LSK  key is \e[0;33m${key_lsk_windows}\e[0m"
		fi
		if [[ -z "${key_ltk_windows}" ]]; then
			nokey='1'
			echo -e "\e[1;31m		* windows LTK  key not found. Please try to remove and pair again this device in windows.\e[0m"
		else
			echo -e "\e[0;32m		- windows LTK  key is \e[1;34m${key_ltk_windows}\e[0m"
		fi
		if [[ -z "${key_es_windows}" ]]; then
			nokey='1'
			echo -e "\e[1;31m		* windows ES   key not found. Please try to remove and pair again this device in windows.\e[0m"
		else
			echo -e "\e[0;32m		- windows ES   key is \e[1;35m${key_es_windows}\e[0m"
		fi
		if [[ -z "${key_ediv_windows}" ]]; then
			nokey='1'
			echo -e "\e[1;31m		* windows EDIV key not found. Please try to remove and pair again this device in windows.\e[0m"
		else
			echo -e "\e[0;32m		- windows EDIV key is \e[1;35m${key_ediv_windows}\e[0m"
		fi
		if [[ -z "${key_rand_windows}" ]]; then
			nokey='1'
			echo -e "\e[1;31m		* windows RAND key not found. Please try to remove and pair again this device in windows.\e[0m"
		else
			echo -e "\e[0;32m		- windows RAND key is \e[1;36m${key_rand_windows}\e[0m"
		fi
	fi
}

function compare_bt_keys() {

	unset different
	if [[ "${bt_device_type}" = 'standard' ]]; then
		if [[ "${key_lk_linux}" != "${key_lk_windows}" ]]; then
			different='true'
		fi
	elif [[ "${bt_device_type}" = 'ble' ]]; then
		if [[ "${key_irk_linux}" != "${key_irk_windows}" ]]; then
			different='true'
		fi
		if [[ "${key_lsk_linux}" != "${key_lsk_windows}" ]]; then
			different='true'
		fi
		if [[ "${key_ltk_linux}" != "${key_ltk_windows}" ]]; then
			different='true'
		fi
		if [[ "${key_es_linux}" != "${key_es_windows}" ]]; then
			different='true'
		fi
		if [[ "${key_ediv_linux}" != "${key_ediv_windows}" ]]; then
			different='true'
		fi
		if [[ "${key_rand_linux}" != "${key_rand_windows}" ]]; then
			different='true'
		fi
	fi
}

function bt_keys_sync_common() {

	unset bt_keys_sync_from_os
	retry='0'
	while true; do
		if [[ "${only_list}" = 'true' ]] || [[ "${skip}" = 'true' ]] || [[ "${retry}" -eq '10' ]]; then
			bt_devices_not_synced+="- bluetooth controller: ${bt_controller_macaddr} \ bluetooth device: ${bt_device_macaddr} - ${bt_device_name}\n"
			if [[ "${only_list}" = 'true' ]] || [[ "${skip}" = 'true' ]]; then
				echo -e "\e[1;33m		* skipping this device\e[0m"
				unset skip
			elif [[ "${retry}" -eq '10' ]]; then
				echo -e "\e[1;31m		* error while updating the key!\e[0m"
			fi
			break
		fi
		if [[ "${different}" = 'true' ]]; then
			if [[ "${keys_ask}" = 'true' ]]; then
				bt_keys_sync_ask
				retry='0'
			elif [[ "${keys_from}" = 'linux' ]]; then
				bt_keys_sync_from_linux
			elif [[ "${keys_from}" = 'windows' ]]; then
				bt_keys_sync_from_windows
			fi
			compare_bt_keys
		fi
		if [[ "${different}" != 'true' ]]; then
			echo -e "\e[1;32m		* keys are synced\e[0m"
			noerror='1'
			if [[ "${bt_keys_sync_from_os}" = 'windows' ]]; then
				check_sudo
				sudo cp "${tmp_dir}/${tmp_info_new}" "/var/lib/bluetooth/${bt_controller_macaddr}/${bt_device_macaddr}/info"
				bt_devices_sync_from_windows+="- bluetooth controller: ${bt_controller_macaddr} \ bluetooth device: ${bt_device_macaddr} - ${bt_device_name}\n"
			elif [[ "${bt_keys_sync_from_os}" = 'linux' ]]; then
				check_sudo
				sudo cp "${tmp_dir}/${tmp_reg_new}" "${tmp_dir}/${tmp_reg}"
				bt_devices_sync_from_linux+="- bluetooth controller: ${bt_controller_macaddr} \ bluetooth device: ${bt_device_macaddr} - ${bt_device_name}\n"
			fi
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
	check_sudo
	sudo cp "/var/lib/bluetooth/${bt_controller_macaddr}/${bt_device_macaddr}/info" "${tmp_dir}/${tmp_info_new}"
	if [[ "${bt_device_type}" = 'standard' ]]; then
		check_sudo
		sudo sed -i "s/${key_lk_linux}/${key_lk_windows}/g" "${tmp_dir}/${tmp_info_new}"
	elif [[ "${bt_device_type}" = 'ble' ]]; then
		if [[ "${key_irk_linux}" != "${key_irk_windows}" ]]; then
			check_sudo
			sudo sed -i "s/Key=${key_irk_linux}/Key=${key_irk_windows}/g" "${tmp_dir}/${tmp_info_new}"
		fi
		if [[ "${key_lsk_linux}" != "${key_lsk_windows}" ]]; then
			check_sudo
			sudo sed -i "s/Key=${key_lsk_linux}/Key=${key_lsk_windows}/g" "${tmp_dir}/${tmp_info_new}"
		fi
		if [[ "${key_ltk_linux}" != "${key_ltk_windows}" ]]; then
			check_sudo
			sudo sed -i "s/Key=${key_ltk_linux}/Key=${key_ltk_windows}/g" "${tmp_dir}/${tmp_info_new}"
		fi
		if [[ "${key_es_linux}" != "${key_es_windows}" ]]; then
			check_sudo
			sudo sed -i "s/EncSize=${key_es_linux}/EncSize=${key_es_windows}/g" "${tmp_dir}/${tmp_info_new}"
		fi
		if [[ "${key_ediv_linux}" != "${key_ediv_windows}" ]]; then
			check_sudo
			sudo sed -i "s/EDiv=${key_ediv_linux}/EDiv=${key_ediv_windows}/g" "${tmp_dir}/${tmp_info_new}"
		fi
		if [[ "${key_rand_linux}" != "${key_rand_windows}" ]]; then
			check_sudo
			sudo sed -i "s/Rand=${key_rand_linux}/Rand=${key_rand_windows}/g" "${tmp_dir}/${tmp_info_new}"
		fi
	fi
	check_sudo
	bt_device_info="$(sudo cat "${tmp_dir}/${tmp_info_new}" 2>/dev/null)"
	get_bt_keys_linux
}

function bt_keys_sync_from_linux() {

	echo -e "\e[1;33m		* updating windows registry key...\e[0m"
	bt_keys_sync_from_os='linux'
	bt_device_info_keys_reg="$(cat -v "${tmp_dir}/${tmp_reg}" | sed 's/\^M//g' | awk "/"${bt_device_windows}]"/,/^$/")"
	cp "${tmp_dir}/${tmp_reg}" "${tmp_dir}/${tmp_reg_new}"
	if [[ "${bt_device_type}" = 'standard' ]]; then
		key_lk_linux_reg="$(echo "${key_lk_linux,,}" | sed 's/.\{2\}/&,/g' | sed 's/.$//')"
		check_sudo
		sudo sed -i "s/\"${bt_device_windows}\"=hex:${key_lk_windows_reg}/\"${bt_device_windows}\"=hex:${key_lk_linux_reg}/g" "${tmp_dir}/${tmp_reg_new}"
	elif [[ "${bt_device_type}" = 'ble' ]]; then
		if [[ "${key_irk_linux}" != "${key_irk_windows}" ]]; then
			key_irk_linux_reg="$(echo "${key_irk_linux,,}" | sed 's/.\{2\}/&,/g' | sed 's/.$//')" # to review
			check_sudo
			sudo sed -i "s/\"IRK\"=hex:${key_irk_windows_reg}/\"IRK\"=hex:${key_irk_linux_reg}/g" "${tmp_dir}/${tmp_reg_new}"
		fi
		if [[ "${key_lsk_linux}" != "${key_lsk_windows}" ]]; then
			key_lsk_linux_reg="$(echo "${key_lsk_linux,,}" | sed 's/.\{2\}/&,/g' | sed 's/.$//')" # to review
			check_sudo
			sudo sed -i "s/\"CSRK\"=hex:${key_lsk_windows_reg}/\"CSRK\"=hex:${key_lsk_linux_reg}/g" "${tmp_dir}/${tmp_reg_new}"
		fi
		if [[ "${key_ltk_linux}" != "${key_ltk_windows}" ]]; then
			key_ltk_linux_reg="$(echo "${key_ltk_linux,,}" | sed 's/.\{2\}/&,/g' | sed 's/.$//')" # to review
			check_sudo
			sudo sed -i "s/\"LTK\"=hex:${key_ltk_windows_reg}/\"LTK\"=hex:${key_ltk_linux_reg}/g" "${tmp_dir}/${tmp_reg_new}"
		fi
		if [[ "${key_es_linux}" != "${key_es_windows}" ]]; then
			key_es_linux_reg="$(printf '%x\n' "${key_es_linux}")" # to review
			until [[ "$(echo "${key_es_linux_reg}" | wc -m)" = '8' ]]; do
				key_es_linux_reg="0${key_es_linux_reg}"
			done
			check_sudo
			sudo sed -i "s/\"KeyLength\"=dword:${key_es_linux_reg}/\"KeyLength\"=dword:${key_es_linux_reg}/g" "${tmp_dir}/${tmp_reg_new}"
		fi
		if [[ "${key_ediv_linux}" != "${key_ediv_windows}" ]]; then
			key_ediv_linux_reg="$(printf '%x\n' "${key_ediv_linux}")" # to review
			until [[ "$(echo "${key_ediv_linux_reg}" | wc -m)" = '8' ]]; do
				key_ediv_linux_reg="0${key_ediv_linux_reg}"
			done
			check_sudo
			sudo sed -i "s/\"EDIV\"=dword:${key_ediv_windows_reg}/\"EDIV\"=dword:${key_ediv_linux_reg}/g" "${tmp_dir}/${tmp_reg_new}"
		fi
		if [[ "${key_rand_linux}" != "${key_rand_windows}" ]]; then
			key_rand_linux_hex="$(printf '%x\n' "${key_rand_linux}" | sed 's/.\{2\}/&,/g')" # to review
			key_rand_linux_reverse="$(echo "${key_rand_linux_hex::-1}" | awk -F',' '{ for (i=NF; i>1; i--) printf("%s ",$i); print $1; }')" # to review
			key_rand_linux_reg="${key_rand_linux_reverse//' '/$','}" # to review
			check_sudo
			sudo sed -i "s/\"ERand\"=hex(b):${key_rand_windows_reg}/\"ERand\"=hex(b):${key_rand_linux_reg}/g" "${tmp_dir}/${tmp_reg_new}"
		fi
	fi
	if [[ "${bt_device_type_windows}" = 'standard' ]]; then
		bt_device_info_keys_reg="$(cat -v "${tmp_dir}/${tmp_reg_new}" | sed 's/\^M//g' | awk "/"${bt_controller_windows}]"/,/^$/" | grep "${bt_device_windows}" | grep -Eo "([[:xdigit:]]{1,2},){15}[[:xdigit:]]{2}$")"
	elif [[ "${bt_device_type_windows}" = 'ble' ]]; then
		bt_device_info_keys_reg="$(cat -v "${tmp_dir}/${tmp_reg_new}" | sed 's/\^M//g' | awk "/"${bt_device_windows}]"/,/^$/")"
	fi
	get_bt_keys_windows
}

function bt_keys_sync() {

	check_sudo
	if ! sudo bash -c "command -v reged" >/dev/null; then
		echo -e "\e[1;31mERROR: This script require \e[1;34mchntpw\e[1;31m. Use e.g. \e[1;34msudo apt install chntpw\e[0m"
		exit 1
	fi

	if ! [[ -f "${tmp_dir}/${tmp_hive}" ]] || ! cmp -s "${system_hive}" "${tmp_dir}/${tmp_hive}"; then
			if ! cp "${system_hive}" "${tmp_dir}/${tmp_hive}"; then
				echo -e "\e[1;31m* error while copying windows SYSTEM registry hive to ${tmp_dir}/${tmp_hive}\e[0m"
				exit 1
			fi
	fi

	check_sudo
	if sudo reged -x "${tmp_dir}/${tmp_hive}" "HKEY_LOCAL_MACHINE\SYSTEM" "\\${control_set}\Services\BTHPORT\Parameters\Keys" "${tmp_dir}/${tmp_reg}"; then
		if [[ -f "${tmp_dir}/${tmp_reg}" ]] && cat -v "${tmp_dir}/${tmp_reg}" | sed 's/\^M//g' | grep -Fq "HKEY_LOCAL_MACHINE\SYSTEM\\${control_set}\Services\BTHPORT\Parameters\Keys"; then
			check_bt_controllers
			if [[ -z "${bt_devices_not_synced}" ]] && [[ "${noerror}" = '1' ]] && [[ -z "${bt_devices_sync_from_linux}" ]] && [[ -z "${bt_devices_sync_from_windows}" ]]; then
				if [[ "${nokey_warn}" = '1' ]]; then
					color='1;33'
				else
					color='1;32'
				fi
				echo
				echo -e "\e[${color}m----------------------------------------------------------------------\e[0m"
				echo -e "\e[${color}m                            Nothing to do.\e[0m"
				echo -e "\e[${color}m----------------------------------------------------------------------\e[0m"
			else
				if [[ "${noerror}" != '1' ]]; then
					echo
					echo -e "\e[1;33m----------------------------------------------------------------------\e[0m"
					echo -e "\e[1;33m----------------------------------------------------------------------\e[0m"
					echo -e "\e[1;33mPlease make sure the bluetooth devices are paired in both linux and windows!\e[0m"
					echo -e "\e[1;33m----------------------------------------------------------------------\e[0m"
					echo -e "\e[1;33m----------------------------------------------------------------------\e[0m"
				fi
				if [[ -n "${bt_devices_not_synced}" ]]; then
					echo
					echo -e "\e[1;33m----------------------------------------------------------------------\e[0m"
					echo -e "\e[1;33m----------------------------------------------------------------------\e[0m"
					echo -e "\e[1;33mThe bluetooth pairing keys from the following devices are not synced:\e[0m"
					echo -e "${bt_devices_not_synced}"
					echo -e "\e[1;33m----------------------------------------------------------------------\e[0m"
					echo -e "\e[1;33m----------------------------------------------------------------------\e[0m"
				fi
				if [[ -n "${bt_devices_sync_from_windows}" ]]; then
					echo
					echo -e "\e[1;32m----------------------------------------------------------------------\e[0m"
					echo -e "\e[1;32m----------------------------------------------------------------------\e[0m"
					echo -e "\e[1;32m- The windows bluetooth pairing keys from the following devices have been imported to linux:\e[0m"
					echo -e "${bt_devices_sync_from_windows}"
					echo -e "\e[1;32m- The os in wich you last paired these devices has the newer working keys\e[0m"
					echo -e "\e[1;32m  so make sure that windows is the last os in which you paired these bluetooth devices!\e[0m"
					echo -e "\e[1;32m- If not, boot into windows and pair them there (if yet paired, remove them first) so windows has the newer working keys\e[0m"
					echo -e "\e[1;32m  then boot into linux and run ${bt_keys_sync_name} again.\e[0m"
					echo
					echo -e "\e[1;32m- restarting bluetooth service...\e[0m"
					check_sudo
					sudo systemctl restart bluetooth
					echo -e "\e[1;32m----------------------------------------------------------------------\e[0m"
					echo -e "\e[1;32m-------------------------------- done --------------------------------\e[0m"
					echo -e "\e[1;32m----------------------------------------------------------------------\e[0m"
				fi

				if [[ -n "${bt_devices_sync_from_linux}" ]]; then
					echo
					echo -e "\e[1;31m----------------------------------------------------------------------\e[0m"
					echo -e "\e[1;31m----------------------------------------------------------------------\e[0m"
					echo -e "\e[1;31m- The linux bluetooth pairing keys from the following devices haven't yet been imported to the windows SYSTEM registry hive:\e[0m"
					echo -e "${bt_devices_sync_from_linux}"
					echo -e "\e[1;31m- This procedure is risky as it could mess with the windows registry.\e[0m"
					echo -e "\e[1;31m  The os in wich you last paired these devices has the newer working keys\e[0m"
					echo -e "\e[1;31m  so the recommended procedure is to boot into windows and pair them there (if yet paired, remove them first) so windows has the newer working keys\e[0m"
					echo -e "\e[1;31m  then boot into linux, run ${bt_keys_sync_name} and always choose \"windows key\" when prompted \"which pairing key you want to use?\" (or use option --windows-keys).\e[0m"
					echo
					echo -e "\e[1;31m- If you, at your own risk, decide to import the bluetooth pairing keys from linux to windows (this has been tested on windows 10 only)\e[0m"
					echo -e "\e[1;31m  a backup of the windows SYSTEM registry hive file will be created, so in case of problems you could try to restore it.\e[0m"

					if [[ -f "${system_hive%/*}/SOFTWARE" ]]; then
						check_sudo
						wait $(sudo reged -x "${system_hive%/*}/SOFTWARE" "HKEY_LOCAL_MACHINE\SOFTWARE" "Microsoft\Windows NT\CurrentVersion" "${tmp_dir}/${tmp_ver}") 2>/dev/null
						win_version="$(cat -v "${tmp_dir}/${tmp_ver}" | sed 's/\^M//g' | grep "\"ProductName\"" | awk -F'=' '{print $2}')"
						win_version="${win_version//\"/$''}"
						if [[ -n "${win_version}" ]]; then
							echo
							echo -e "\e[1;31m* Your windows version seems to be: ${win_version}\e[0m"
						else
							echo
							echo -e "\e[1;31m* Unable to retrieve windows version!\e[0m"
						fi
					else
						echo
						echo -e "\e[1;31m* Unable to retrieve windows version!\e[0m"
					fi

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
							if cp "${system_hive}" "${system_hive}_${backup_date}.bak"; then
								echo
								echo -e "\e[1;31m- importing the linux bluetooth pairing keys to the windows SYSTEM registry hive...\e[0m"
								check_sudo
								sudo reged -ICN "${tmp_dir}/${tmp_hive}" "HKEY_LOCAL_MACHINE\SYSTEM" "${tmp_dir}/${tmp_reg}"
								if cp "${tmp_dir}/${tmp_hive}" "${system_hive}"; then
									break
								else
									echo -e "\e[1;31m- error while importing the linux bluetooth pairing keys to the windows SYSTEM registry hive\e[0m"
									echo -e "\e[1;31m- restoring backup\e[0m"
									if cp "${system_hive}_${backup_date}.bak" "${system_hive}"; then
										echo -e "\e[1;31m- backup restored\e[0m"
										exit 1
									else
										echo -e "\e[1;31m- error while restoring the backup!\e[0m"
										exit 1
									fi
								fi
							else
								echo -e "\e[1;31m- error while making the backup of the windows SYSTEM registry hive file\e[0m"
								echo -e "\e[1;31m- aborting\e[0m"
								exit 1
							fi
						fi
					done
					echo -e "\e[1;31m----------------------------------------------------------------------\e[0m"
					echo -e "\e[1;31m-------------------------------- done --------------------------------\e[0m"
					echo -e "\e[1;31m----------------------------------------------------------------------\e[0m"
				fi
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

	if [[ "${sudouser}" != '1' ]]; then
		current_sudo="$(date +%s)"
		if [[ -z "${last_sudo}" ]] || [[ "$(echo "$((${current_sudo}-${last_sudo})) >= ${timestamp_timeout}" | bc -l)" = '1' ]]; then
			while true; do
				echo -e "\e[1;33mIn order to proceed you must grant root permissions\e[0m"
				if sudo -v; then
					if [[ -z "${timestamp_timeout}" ]]; then
						timestamp_timeout_users="$(sudo cat /etc/sudoers | grep 'timestamp_timeout')"
						if echo "${timestamp_timeout_users}" | grep 'timestamp_timeout' | grep -q "^Defaults:${myuser} \+"; then
							timestamp_timeout="$(echo - | awk "{print "60" * "$(echo "${timestamp_timeout_users}" | grep 'timestamp_timeout' | grep "^Defaults:${myuser} \+" | awk -F'=' '{print $2}' | sort -g | head -n 1)"}")"
						elif echo "${timestamp_timeout_users}" | grep 'timestamp_timeout' | grep -q "^Defaults \+"; then
							timestamp_timeout="$(echo - | awk "{print "60" * "$(echo "${timestamp_timeout_users}" | grep 'timestamp_timeout' | grep '^Defaults \+' | awk -F'=' '{print $2}' | sort -g | head -n 1)"}")"
						else
							timestamp_timeout='900'
						fi

						sudo_timeout='1.2'
						if [[ "$(echo "${timestamp_timeout} >= 0" | bc -l)" = '1' ]] && [[ "$(echo "${timestamp_timeout} < ${sudo_timeout}" | bc -l)" = '1' ]]; then
							if [[ "${EUID}" != '0' ]]; then
								if [[ "${timestamp_timeout}" = '0' ]]; then
									echo -e "\e[1;31m* Your system is configured to ask for password at every sudo command.\e[0m"
								else
									echo -e "\e[1;31m* The timeout for sudo is too low.\e[0m"
								fi
								echo -e "\e[1;31m* Please run ${bt_keys_sync_name} as root.\e[0m"
								force_exit='1'
								exit 1
							fi
						fi

						if [[ "$(echo "${timestamp_timeout} >= ${sudo_timeout}" | bc -l)" = '1' ]]; then
							if [[ "${EUID}" = '0' ]]; then
								echo -e "\e[1;31m* no need to run ${bt_keys_sync_name} as root.\e[0m"
								echo -e "\e[1;31m* ${bt_keys_sync_name} will ask to grant root permission when needed.\e[0m"
								echo -e "\e[1;31m* please run ${bt_keys_sync_name} as normal user.\e[0m"
								exit 1
							fi
						fi

						if [[ "${EUID}" = '0' ]]; then
							echo -e "\e[1;33m* warning: ${bt_keys_sync_name} running as root.\e[0m"
							sudouser='1'
						fi
					fi
					last_sudo="$(date +%s)"
					break
				else
					echo -e "\e[1;31mPermission denied! Press ENTER to exit or wait 5 seconds to retry\e[0m"
					if read -t 5 _e; then
						exit 1
					fi
				fi
			done
		fi
	fi
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

function cleaning() {

	if [[ "${force_exit}" != '1' ]]; then
		if [[ -f "${tmp_dir}/${tmp_reg}" ]]; then
			check_sudo
			sudo rm "${tmp_dir}/${tmp_reg}"
		fi
		if [[ -f "${tmp_dir}/${tmp_reg_new}" ]]; then
			check_sudo
			sudo rm "${tmp_dir}/${tmp_reg_new}"
		fi
		if [[ -f "${tmp_dir}/${tmp_devs}" ]]; then
			check_sudo
			sudo rm "${tmp_dir}/${tmp_devs}"
		fi
		if [[ -f "${tmp_dir}/${tmp_ver}" ]]; then
			check_sudo
			sudo rm "${tmp_dir}/${tmp_ver}"
		fi
		if [[ -f "${tmp_dir}/${tmp_info_new}" ]]; then
			check_sudo
			sudo rm "${tmp_dir}/${tmp_info_new}"
		fi
	fi
	sudo -k

	if ! grep -Eqs "^Exec=${bt_keys_sync_name}$" "$HOME/.local/share/applications/bt-keys-sync.desktop" && [[ "${EUID}" != '0' ]]; then
		echo
		echo -e "\e[1;34m-----------------------------------------------------------------------------\e[0m"
		echo -e "\e[1;34m* Creating bt-keys-sync menu item in Categories AudioVideo, Audio and Utility\e[0m"
		echo -e "\e[1;34m-----------------------------------------------------------------------------\e[0m"
		sh -c 'echo "[Desktop Entry]
Name=bt-keys-sync
Exec="${bt_keys_sync_name}"
Icon=bluetooth
Terminal=true
Type=Application
StartupNotify=false
Categories=AudioVideo;Audio;Utility;
" > $HOME/.local/share/applications/bt-keys-sync.desktop'
	fi

	echo
	echo -e "\e[1;32mPress ENTER to exit\e[0m"
	if read -sr _e; then
		exit 1
	fi
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

# Version:    0.3.10
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

### About Bluetooth Low Energy (BLE)
Bluetooth Low Energy Device (BLE) can be detected, but key checks will be skipped.
Please take a look here: https://github.com/KeyofBlueS/bt-keys-sync/issues/13

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
-o, --only-list                  Only list bluetooth devices and pairing keys, don't do anything else.
-h, --help                       Show this help.
"
}

trap cleaning EXIT

bt_keys_sync_name="$(echo "${0}" | rev | awk -F'/' '{print $1}' | rev)"
if ! command -v "${bt_keys_sync_name}" > /dev/null; then
	bt_keys_sync_name="$(readlink -f "${0}")"
fi
export bt_keys_sync_name

printf "\033]2;${bt_keys_sync_name}\a"

sudo -k
myuser="${USER}"
tmp_dir='/tmp'
tmp_reg='bt_reg_keys.reg'
tmp_reg_new='bt_reg_keys_new.reg'
tmp_devs='bt_reg_devs.reg'
tmp_ver='bt_reg_ver.reg'
tmp_hive='SYSTEM_hive_win'
tmp_info_new='bt_info_keys_new'
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

echo
echo '# bt-keys-sync'
echo

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
