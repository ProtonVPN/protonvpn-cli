#!/usr/bin/env bash
######################################################
# ProtonVPN CLI
# ProtonVPN Command-Line Tool
#
# Made with <3 for Linux + macOS.
###
#Author: Mazin Ahmed <Mazin AT ProtonMail DOT ch>
######################################################


if [[ ("$UID" != 0) && ("$1" != "ip") && ("$1" != "-ip") && \
      ("$1" != "--ip") && !( -z "$1") && ("$1" != "-h") && \
      ("$1" != "--help") && ("$1" != "--h") && ("$1" != "-help") && \
      ("$1" != "help") ]]; then
  echo "[!] Error: The program requires root access."
  exit 1
fi

function check_requirements() {
  if [[ $(which openvpn) == "" ]]; then
    echo "[!] Error: openvpn is not installed. Install \`openvpn\` package to continue."
    exit 1
  fi
  if [[ $(which python) == "" ]]; then
    echo "[!] Error: python is not installed. Install \`python\` package to continue."
    exit 1
  fi
  if [[ $(which dialog) == "" ]]; then
    echo "[!] Error: dialog is not installed. Install \`dialog\` package to continue."
    exit 1
  fi
  if [[ $(which wget) == "" ]]; then
    echo "[!] Error: wget is not installed. Install \`wget\` package to continue."
    exit 1
  fi

  if [[ $(which sysctl) == "" ]]; then
    echo "[!] Error: sysctl is not installed. Install \`sysctl\` package to continue."
    exit 1
  fi

  if [[ $(which sha512sum) == "" ]]; then
    echo "[!] Error: sha512sum is not installed. Install \`sha512sum\` package to continue."
    echo "Also check: https://github.com/ProtonVPN/protonvpn-cli/issues/45 for reference."
    exit 1
  fi

  if [[ ! -x "/etc/openvpn/update-resolv-conf" ]]; then
    echo "[!] Error: openvpn-resolv-conf is not installed."
    read -p "Would you like protonvpn-cli to install openvpn-resolv-conf? (y/n): " "user_confirm"
    if [[ "$user_confirm" == "y" ]]; then
      install_openvpn_update_resolv_conf
    else
      exit 1
    fi
  fi
}

function get_home() {
  if [[ -z "$SUDO_USER" ]]; then
    CURRENT_USER="$(whoami)"
  else
    CURRENT_USER="$SUDO_USER"
  fi
  USER_HOME=$(getent passwd "$CURRENT_USER" 2> /dev/null | cut -d: -f6)
  if [[ -z "$USER_HOME" ]]; then
    USER_HOME="$HOME"
  fi
  echo "$USER_HOME"
}

function get_protonvpn_cli_home() {
  echo "$(get_home)/.protonvpn-cli"
}

function install_openvpn_update_resolv_conf() {
  if [[ ("$UID" != 0) ]]; then
    echo "[!] Error: installation requires root access."
    exit 1
  fi
  echo "[*] Installing openvpn-update-resolv-conf"
  mkdir -p "/etc/openvpn/"
  file_sha512sum="81cf5ed20ec2a2f47f970bb0185fffb3e719181240f2ca3187dbee1f4d102ce63ab048ffee9daa6b68c96ac59d1d86ad4de2b1cfaf77f1b1f1918d143e96a588"
  wget "https://raw.githubusercontent.com/ProtonVPN/scripts/master/update-resolv-conf.sh" -O "/etc/openvpn/update-resolv-conf"
  if [[ ($? == 0) && ($(sha512sum "/etc/openvpn/update-resolv-conf" | cut -d " " -f1) == "$file_sha512sum")  ]]; then
    chmod +x "/etc/openvpn/update-resolv-conf"
    echo "[*] Done."
  else
    echo "[!] Error installing openvpn-update-resolv-conf"
    exit 1
  fi
}


function check_ip() {
  counter=0
  ip=""
  while [[ "$ip" == "" ]]; do
    if [[ $counter -gt 0 ]]; then
      sleep 2
    fi

    if [[ $counter -lt 3 ]]; then
      ip=$(wget --header 'x-pm-appversion: Other' --header 'x-pm-apiversion: 3' \
        --header 'Accept: application/vnd.protonmail.v1+json' \
        --timeout 6 -q -O /dev/stdout 'https://api.protonmail.ch/vpn/location' \
        | awk -F'"' '$2 == "IP" { print $4 }')
      counter=$((counter+1))
    else
      ip="Error."
    fi
  done
  echo "$ip"
}

function cli_debug() {
  if [[ "$PROTONVPN_CLI_DEBUG" == "true" ]]; then
    if [[ "$1" == "stdout" ]]; then
      echo "$2" > "/dev/stdout"
    elif [[ "$1" == "stderr" ]]; then
      echo "$2" > "/dev/stderr"
    fi
  fi
}

function init_cli() {
  if [[ -f "$(get_protonvpn_cli_home)/protonvpn_openvpn_credentials" ]]; then
    echo -n "[!] user profile for protonvpn-cli has already been initialized. Would you like to start over with a fresh configuration? [Y/N]: "
    read "reset_profile"
  fi
  if  [[ ("$reset_profile" == "n" || "$reset_profile" == "N") ]]; then
     echo "[*] Profile initialization canceled."
     exit 0
  fi

  rm -rf "$(get_protonvpn_cli_home)/"  # Previous profile will be removed/overwritten, if any.
  mkdir -p "$(get_protonvpn_cli_home)/"

  read -p "Enter OpenVPN username: " "openvpn_username"
  read -s -p "Enter OpenVPN password: " "openvpn_password"
  echo -e "$openvpn_username\n$openvpn_password" > "$(get_protonvpn_cli_home)/protonvpn_openvpn_credentials"
  chown "$USER:$(id -gn $USER)" "$(get_protonvpn_cli_home)/protonvpn_openvpn_credentials"
  chmod 0400 "$(get_protonvpn_cli_home)/protonvpn_openvpn_credentials"

  echo -e "\n[.] ProtonVPN Plans:\n1) Free\n2) Basic\n3) Plus\n4) Visionary"
  protonvpn_tier=""
  available_plans=(1 2 3 4)
  while [[ $protonvpn_tier == "" ]]; do
    read -p "Enter Your ProtonVPN plan ID: " "protonvpn_plan"
    case "${available_plans[@]}" in  *"$protonvpn_plan"*)
      protonvpn_tier=$((protonvpn_plan-1))
      ;;
    4)
      protonvpn_tier=$((protonvpn_tier-1)) # Visionary gives access to the same VPNs as Plus.
      ;;
    *)
      echo "Invalid input."
    ;; esac
  done
  echo -e "$protonvpn_tier" > "$(get_protonvpn_cli_home)/protonvpn_tier"
  chown "$USER:$(id -gn $USER)" "$(get_protonvpn_cli_home)/protonvpn_tier"
  chmod 0400 "$(get_protonvpn_cli_home)/protonvpn_tier"

  chown -R "$USER:$(id -gn $USER)" "$(get_protonvpn_cli_home)/"
  chmod -R 0400 "$(get_protonvpn_cli_home)/"

  echo "[*] Done."

}

function detect_machine_type() {
  unameOut="$(uname -s)"
  case "${unameOut}" in
    Linux*)     machine=Linux;;
    Darwin*)    machine=Mac;;
    CYGWIN*)    machine=Cygwin;;
    MINGW*)     machine=MinGw;;
    *)          machine="UNKNOWN"
  esac
  echo "$machine"
}

function manage_ipv6() {
  # ProtonVPN support for IPv6 coming soon.
  errors_counter=0
  if [[ ("$1" == "disable") && ( $(detect_machine_type) != "Mac" ) ]]; then
    if [ ! -z "$(ip -6 a 2> /dev/null)" ]; then

      # Save linklocal address and disable IPv6.
      ip -6 a | awk '/^[0-9]/ {DEV=$2}/inet6 fe80/ {print substr(DEV,1,length(DEV)-1) " " $2}' > "$(get_protonvpn_cli_home)/.ipv6_address"
      if [[ $? != 0 ]]; then errors_counter=$((errors_counter+1)); fi

      sysctl -w net.ipv6.conf.all.disable_ipv6=1 &> /dev/null
      if [[ $? != 0 ]]; then errors_counter=$((errors_counter+1)); fi

      sysctl -w net.ipv6.conf.default.disable_ipv6=1 &> /dev/null
      if [[ $? != 0 ]]; then errors_counter=$((errors_counter+1)); fi

    fi
  fi

  # Disable IPv6 in macOS.
  if [[ ("$1" == "disable") &&  ( $(detect_machine_type) == "Mac" ) ]]; then
    # Get list of services and remove the first line which contains a heading.
    ipv6_services="$( networksetup  -listallnetworkservices | sed -e '1,1d')"

    # Go through the list disabling IPv6 for enabled services, and outputting lines with the names of the services.
    echo %s "$ipv6_services" | \

    while read ipv6_service ; do
      # If first character of a line is an asterisk, the service is disabled, so we skip it.
      if [[ "${ipv6_service:0:1}" != "*" ]] ; then
        ipv6_status="$( networksetup -getinfo "$ipv6_service" | grep 'IPv6: ' | sed -e 's/IPv6: //')"
        if [[ "$ipv6_status" = "Automatic" ]] ; then
          networksetup -setv6off "$ipv6_service"
          echo "$ipv6_service" >> "$(get_protonvpn_cli_home)/.ipv6_services"
        fi
      fi
    done

  fi

  if [[ ("$1" == "enable") && ( ! -f "$(get_protonvpn_cli_home)/.ipv6_address" ) && ( $(detect_machine_type) != "Mac" ) ]]; then
    echo "[!] This is an error in enabling ipv6 on the machine. Please enable it manually."
  fi

  if [[ ("$1" == "enable") && ( -f "$(get_protonvpn_cli_home)/.ipv6_address" ) && ( $(detect_machine_type) != "Mac" ) ]]; then
    sysctl -w net.ipv6.conf.all.disable_ipv6=0 &> /dev/null
    if [[ $? != 0 ]]; then errors_counter=$((errors_counter+1)); fi

    sysctl -w net.ipv6.conf.default.disable_ipv6=0 &> /dev/null
    if [[ $? != 0 ]]; then errors_counter=$((errors_counter+1)); fi

    # Restore linklocal on default interface.
    while read -r DEV ADDR; do
      ip addr add "$ADDR" dev "$DEV"  &> /dev/null
      if [[ ($? != 0) && ($? != 2) ]]; then errors_counter=$((errors_counter+1)) ; fi
    done < "$(get_protonvpn_cli_home)/.ipv6_address"

    rm -f "$(get_protonvpn_cli_home)/.ipv6_address"
  fi


  if [[ ("$1" == "enable") && ( ! -f "$(get_protonvpn_cli_home)/.ipv6_services" ) && ( $(detect_machine_type) == "Mac" ) ]]; then
    echo "[!] This is an error in enabling ipv6 on the machine. Please enable it manually."
  fi

  # Restore IPv6 in macOS.
  if [[ ("$1" == "enable") && ( -f "$(get_protonvpn_cli_home)/.ipv6_services" ) && ( $(detect_machine_type) == "Mac" ) ]]; then
    if [[ $(cat "$(get_protonvpn_cli_home)/.ipv6_services") == "" ]] ; then
      return
    fi

    ipv6_service=$(cat "$(get_protonvpn_cli_home)/.ipv6_services")

    while read ipv6_service ; do
      networksetup -setv6automatic "$ipv6_service"
    done < "$(get_protonvpn_cli_home)/.ipv6_services"

    rm -f "$(get_protonvpn_cli_home)/.ipv6_services"
  fi

  if [[ $errors_counter != 0 ]]; then
    echo "[!] There are issues in managing ipv6 in the system. Please test the system for the root cause."
    echo "Not able to manage ipv6 by protonvpn-cli might cause issues in leaking the system's ipv6 address."
  fi
}

function modify_dns_resolvconf() {

  if [[ ("$1" == "backup_resolvconf") &&  ( $(detect_machine_type) != "Mac" ) ]]; then
    cp "/etc/resolv.conf" "/etc/resolv.conf.protonvpn_backup" # backing-up current resolv.conf
  fi

  #if [[ ("$1" == "backup_resolvconf") &&  ( $(detect_machine_type) == "Mac" ) ]]; then
  #  ToDo: Support for macOS
  #fi

  if [[ ("$1" == "to_protonvpn_dns") &&  ( $(detect_machine_type) != "Mac") ]]; then
    if [[ $(cat "$(get_protonvpn_cli_home)/protonvpn_tier") == "0" ]]; then
      dns_server="10.8.0.1" # free tier dns
    else
      dns_server="10.8.8.1" # paid tier dns
    fi
    echo -e "# ProtonVPN DNS - protonvpn-cli\nnameserver $dns_server" > "/etc/resolv.conf"
  fi

  #if [[ ("$1" == "to_protonvpn_dns") &&  ( $(detect_machine_type) == "Mac" ) ]]; then
  #  ToDo: Support for macOS
  #fi

  if [[ "$1" == "revert_to_backup" &&  ( $(detect_machine_type) != "Mac" )  ]]; then
    cp "/etc/resolv.conf.protonvpn_backup" "/etc/resolv.conf"
  fi

  #if [[ ("$1" == "revert_to_backup") &&  ( $(detect_machine_type) == "Mac" ) ]]; then
  #  ToDo: Support for macOS
  #fi
}

function is_openvpn_currently_running() {
  if [[ $(pgrep openvpn) == "" ]]; then
    echo false
  else
    echo true
  fi
}

function openvpn_disconnect() {
  max_checks=3
  counter=0

  if [[ "$1" != "quiet" ]]; then
    echo "Disconnecting..."
  fi

  while [[ $counter -lt $max_checks ]]; do
      pkill -f openvpn
      sleep 0.50
      if [[ $(is_openvpn_currently_running) == false ]]; then
        modify_dns_resolvconf revert_to_backup # Reverting to original resolv.conf
        manage_ipv6 enable # Enabling IPv6 on machine.
        if [[ "$1" != "quiet" ]]; then
          echo "[#] Disconnected."
          echo "[#] Current IP: $(check_ip)"
        fi

        if [[ "$2" != "dont_exit" ]]; then
          exit 0
        fi

      fi
    counter=$((counter+1))
  done
  if [[ "$1" != "quiet" ]]; then
    echo "[!] Error disconnecting OpenVPN."

    if [[ "$2" != "dont_exit" ]]; then
      exit 1
    fi

  fi
}

function openvpn_connect() {
  if [[ $(is_openvpn_currently_running) == true ]]; then
    echo "[!] Error: OpenVPN is already running on this machine."
    exit 1
  fi

  modify_dns_resolvconf backup_resolvconf # backuping-up current resolv.conf
  manage_ipv6 disable # Disabling IPv6 on machine.

  config_id=$1
  selected_protocol=$2
  if [[ $selected_protocol == "" ]]; then
    selected_protocol="udp"  # Default protocol
  fi

  current_ip="$(check_ip)"
  if [[ "$PROTONVPN_CLI_LOG" == "true" ]]; then  # PROTONVPN_CLI_LOG is retrieved from env.
    tempfile=$(mktemp -t protonvpn-cli-logs-XXXXXXXX)
    if [[ $? != 0 ]]; then echo "[!] Error creating logging file."; exit 1; fi
    echo "[*] CLI logging mode enabled."
    echo -e "[*] Saving logs to: $tempfile"

    wget --header 'x-pm-appversion: Other' --header 'x-pm-apiversion: 3' \
      --header 'Accept: application/vnd.protonmail.v1+json' \
      --timeout 10 -q -O /dev/stdout "https://api.protonmail.ch/vpn/config?Platform=linux&ServerID=$config_id&Protocol=$selected_protocol" \
      | openvpn --daemon --config "/dev/stdin" --auth-user-pass "$(get_protonvpn_cli_home)/protonvpn_openvpn_credentials" --auth-nocache --auth-retry nointeract --verb 4 --log-append "$tempfile" &> "$tempfile"
  else
    wget --header 'x-pm-appversion: Other' --header 'x-pm-apiversion: 3' \
      --header 'Accept: application/vnd.protonmail.v1+json' \
      --timeout 10 -q -O /dev/stdout "https://api.protonmail.ch/vpn/config?Platform=linux&ServerID=$config_id&Protocol=$selected_protocol" \
      | openvpn --daemon --config "/dev/stdin" --auth-user-pass "$(get_protonvpn_cli_home)/protonvpn_openvpn_credentials" --auth-nocache --auth-retry nointeract
  fi
  echo "Connecting..."

  max_checks=3
  counter=0
  while [[ $counter -lt $max_checks ]]; do
    sleep 5
    new_ip="$(check_ip)"
    if [[ ("$current_ip" != "$new_ip") && ("$new_ip" != "Error.") ]]; then
      modify_dns_resolvconf to_protonvpn_dns # Use protonvpn DNS server
      echo "[$] Connected!"
      echo "[#] New IP: $new_ip"
      exit 0
    fi

    counter=$((counter+1))
  done
  echo "[!] Error connecting to VPN."
  openvpn_disconnect quiet
  exit 1
}

function update_cli() {
  if [[ "$(check_ip)" == "Error." ]]; then
    echo "[!] Error: There is an internet connection issue."
    exit 1
  fi
  cli_path="/usr/local/bin/protonvpn-cli"
  if [[ ! -f "$cli_path" ]]; then
    echo "[!] Error: protonvpn-cli does not seem to be installed."
    exit 1
  fi
  echo "[#] Checking for update."
  current_local_hashsum=$(sha512sum "$cli_path" | cut -d " " -f1)
  remote_=$(wget --timeout 6 -q -O /dev/stdout 'https://raw.githubusercontent.com/ProtonVPN/protonvpn-cli/master/protonvpn-cli.sh')
  if [[ $? != 0 ]]; then
    echo "[!] Error: There is an error updating protonvpn-cli."
    exit 1
  fi
  remote_hashsum=$( echo "$remote_" | sha512sum | cut -d ' ' -f1)

  if [[ "$current_local_hashsum" == "$remote_hashsum" ]]; then
    echo "[*] protonvpn-cli is up-to-date!"
    exit 0
  else
    echo "[#] A new update is available."
    echo "[#] Updating..."
    wget -q --timeout 20 -O "$cli_path" 'https://raw.githubusercontent.com/ProtonVPN/protonvpn-cli/master/protonvpn-cli.sh'
    if [[ $? == 0 ]]; then
      echo "[#] protonvpn-cli has been updated successfully."
      exit 0
    else
      echo "[!] Error: There is an error updating protonvpn-cli."
      exit 1
    fi
  fi
}

function install_cli() {
  mkdir -p "/usr/bin/" "/usr/local/bin/"
  cli="$( cd "$(dirname "$0")" ; pwd -P )/$0"
  errors_counter=0
  cp "$cli" "/usr/local/bin/protonvpn-cli" &> /dev/null
  if [[ $? != 0 ]]; then errors_counter=$((errors_counter+1)); fi

  ln -s -f "/usr/local/bin/protonvpn-cli" "/usr/local/bin/pvpn" &> /dev/null
  if [[ $? != 0 ]]; then errors_counter=$((errors_counter+1)); fi

  ln -s -f "/usr/local/bin/protonvpn-cli" "/usr/bin/protonvpn-cli" &> /dev/null
  if [[ $? != 0 ]]; then errors_counter=$((errors_counter+1)); fi

  ln -s -f "/usr/local/bin/protonvpn-cli" "/usr/bin/pvpn" &> /dev/null
  if [[ $? != 0 ]]; then errors_counter=$((errors_counter+1)); fi

  chown "$USER:$(id -gn $USER)" "/usr/local/bin/protonvpn-cli" "/usr/local/bin/pvpn" "/usr/bin/protonvpn-cli" "/usr/bin/pvpn" &> /dev/null
  if [[ $? != 0 ]]; then errors_counter=$((errors_counter+1)); fi

  chmod 0755 "/usr/local/bin/protonvpn-cli" "/usr/local/bin/pvpn" "/usr/bin/protonvpn-cli" "/usr/bin/pvpn" &> /dev/null
  if [[ $? != 0 ]]; then errors_counter=$((errors_counter+1)); fi

  if [[ ($errors_counter == 0) || ( $(which protonvpn-cli) != "" ) ]]; then
    echo "[*] Done."
  else
    echo "[!] Error: There was an error in installing protonvpn-cli."
  fi
}

function uninstall_cli() {

  if [[ $(is_openvpn_currently_running) == true ]]; then
    echo "[!] OpenVPN is currently running."
    echo "[!] Session will be disconnected."
    openvpn_disconnect quiet dont_exit
    if [[ $(is_openvpn_currently_running) == true ]]; then  # checking if it OpenVPN is still active.
      echo "[!] Error disconnecting OpenVPN."
      echo "[!] Please disconnect manually and try uninstallation again."
      exit 1
    else
      echo "[#] Disconnected."
    fi
  fi

  errors_counter=0
  rm -f "/usr/local/bin/protonvpn-cli" "/usr/local/bin/pvpn" "/usr/bin/protonvpn-cli" "/usr/bin/pvpn" &> /dev/null
  if [[ $? != 0 ]]; then errors_counter=$((errors_counter+1)); fi

  rm -rf "$(get_protonvpn_cli_home)/" &> /dev/null
  if [[ $? != 0 ]]; then errors_counter=$((errors_counter+1)); fi

  if [[ ($errors_counter == 0) || ( $(which protonvpn-cli) == "" ) ]]; then
    echo "[*] Done."
  else
    echo "[!] Error: There was an error in uninstalling protonvpn-cli."
  fi
}

function check_if_profile_initialized() {
  _=$(cat "$(get_protonvpn_cli_home)/protonvpn_openvpn_credentials" "$(get_protonvpn_cli_home)/protonvpn_tier" &> /dev/null)
  if [[ $? != 0 ]]; then
    echo "[!] Profile is not initialized."
    echo -e "Initialize your profile using: \n    $(basename $0) --init"
    exit 1
  fi
}

function connect_to_fastest_vpn() {
  check_if_profile_initialized
  if [[ $(is_openvpn_currently_running) == true ]]; then
    echo "[!] Error: OpenVPN is already running on this machine."
    exit 1
  fi
  if [[ "$(check_ip)" == "Error." ]]; then
    echo "[!] Error: There is an internet connection issue."
    exit 1
  fi

  echo "Fetching ProtonVPN Servers..."
  config_id=$(get_fastest_vpn_connection_id)
  selected_protocol="udp"
  openvpn_connect "$config_id" "$selected_protocol"
}

function connect_to_random_vpn() {
  check_if_profile_initialized
  if [[ $(is_openvpn_currently_running) == true ]]; then
    echo "[!] Error: OpenVPN is already running on this machine."
    exit 1
  fi
  if [[ "$(check_ip)" == "Error." ]]; then
    echo "[!] Error: There is an internet connection issue."
    exit 1
  fi

  echo "Fetching ProtonVPN Servers..."
  config_id=$(get_random_vpn_connection_id)
  available_protocols=("tcp" "udp")
  selected_protocol=${available_protocols[$RANDOM % ${#available_protocols[@]}]}
  openvpn_connect "$config_id" "$selected_protocol"
}

function connect_to_specific_server() {
  check_if_profile_initialized
  if [[ $(is_openvpn_currently_running) == true ]]; then
    echo "[!] Error: OpenVPN is already running on this machine."
    exit 1
  fi
  if [[ "$(check_ip)" == "Error." ]]; then
    echo "[!] Error: There is an internet connection issue."
    exit 1
  fi

  echo "Fetching ProtonVPN Servers..."

  server_list=$(get_vpn_config_details | tr ' ' '@')
  if [[ "$(echo "$2" | tr '[:upper:]' '[:lower:]')" == "tcp" ]]; then
    protocol="tcp"
  else
    protocol="udp"
  fi

  for i in $server_list; do
    id=$(echo "$i" | cut -d"@" -f1)
    name=$(echo "$i" | cut -d"@" -f2)
    if [[ "$(echo "$1" | tr '[:upper:]' '[:lower:]')" == "$(echo "$name" | tr '[:upper:]' '[:lower:]')"  ]]; then
      openvpn_connect "$id" "$protocol"
    fi
  done

  # If not found in $server_list.
  echo "[!] Error: Invalid server name, or server not accessible with your plan."
  exit 1
}

function connection_to_vpn_via_dialog_menu() {
  check_if_profile_initialized
  if [[ $(is_openvpn_currently_running) == true ]]; then
    echo "[!] Error: OpenVPN is already running on this machine."
    exit 1
  fi
  if [[ "$(check_ip)" == "Error." ]]; then
    echo "[!] Error: There is an internet connection issue."
    exit 1
  fi

  available_protocols=("udp" " " "tcp" " ")
  IFS=$'\n'
  ARRAY=()

  echo "Fetching ProtonVPN Servers..."

  c2=$(get_vpn_config_details)
  counter=0
  for i in $c2; do
    ID=$(echo "$i" | cut -d " " -f1)
    data=$(echo "$i" | tr '@' ' ' | awk '{$1=""; print $0}' | tr ' ' '@')
    counter=$((counter+1))
    ARRAY+=($counter)
    ARRAY+=($data)
  done

  config_id=$(dialog --clear  --ascii-lines --output-fd 1 --title "ProtonVPN-CLI" --column-separator "@" \
    --menu "ID - Name - Country - Load - EntryIP - ExitIP - Features" 35 300 "$((${#ARRAY[@]}))" "${ARRAY[@]}" )
  clear
  if [[ $config_id == "" ]]; then
    exit 2
  fi

  c=1
  for i in $c2; do
    ID=$(echo "$i" | cut -d " " -f1)
    if [[ $c -eq $config_id ]]; then
      ID=$(echo "$i" | cut -d " " -f1)
      config_id=$ID
      break
    fi
    c=$((c+1))
  done

  selected_protocol=$(dialog --clear  --ascii-lines --output-fd 1 --title "ProtonVPN-CLI" \
    --menu "Select Network Protocol" 35 80 2 "${available_protocols[@]}")
  clear
  if [[ $selected_protocol == "" ]]; then
    exit 2
  fi

  openvpn_connect "$config_id" "$selected_protocol"

}
function get_fastest_vpn_connection_id() {
  response_output=$(wget --header 'x-pm-appversion: Other' --header 'x-pm-apiversion: 3' \
    --header 'Accept: application/vnd.protonmail.v1+json' \
    --timeout 20 -q -O /dev/stdout "https://api.protonmail.ch/vpn/logicals")
  tier=$(cat "$(get_protonvpn_cli_home)/protonvpn_tier")
  output=`python <<END
import json, math, random
json_parsed_response = json.loads("""$response_output""")

all_features = {"SECURE_CORE": 1, "TOR": 2, "P2P": 4, "XOR": 8, "IPV6": 16}
excluded_features_on_fastest_connect = ["TOR"]

candidates_1 = []
for _ in json_parsed_response["LogicalServers"]:
    server_features_index = int(_["Features"])
    server_features  = []
    for f in all_features.keys():
        if (server_features_index & all_features[f]) > 0:
            server_features.append(f)
    is_excluded = False
    for excluded_feature in excluded_features_on_fastest_connect:
        if excluded_feature in server_features:
            is_excluded = True
    if is_excluded is True:
        continue
    if (_["Tier"] <= int("""$tier""")):
        candidates_1.append(_)

candidates_2_size = float(len(candidates_1)) / 100.00 * 5.00
candidates_2 = sorted(candidates_1, key=lambda l: l["Score"])[:int(math.ceil(candidates_2_size))]
random_candidate = random.choice(candidates_2)
vpn_connection_id = random.choice(random_candidate["Servers"])["ID"]
print(vpn_connection_id)

END`

  echo "$output"
}

function get_random_vpn_connection_id() {
  response_output=$(wget --header 'x-pm-appversion: Other' --header 'x-pm-apiversion: 3' \
    --header 'Accept: application/vnd.protonmail.v1+json' \
    --timeout 20 -q -O /dev/stdout "https://api.protonmail.ch/vpn/logicals")
  tier=$(cat "$(get_protonvpn_cli_home)/protonvpn_tier")
  output=`python <<END
import json, random
json_parsed_response = json.loads("""$response_output""")
output = []
for _ in json_parsed_response["LogicalServers"]:
    if (_["Tier"] <= int("""$tier""")):
        output.append(_)
print(random.choice(output)["Servers"][0]["ID"])
END`

  echo "$output"
}

function get_vpn_config_details() {
  response_output=$(wget --header 'x-pm-appversion: Other' --header 'x-pm-apiversion: 3' \
    --header 'Accept: application/vnd.protonmail.v1+json' \
    --timeout 20 -q -O /dev/stdout "https://api.protonmail.ch/vpn/logicals")
  tier=$(cat "$(get_protonvpn_cli_home)/protonvpn_tier")
  output=`python <<END
import json, random
json_parsed_response = json.loads("""$response_output""")
output = []
for _ in json_parsed_response["LogicalServers"]:
    if (_["Tier"] <= int("""$tier""")):
        output.append(_)
all_features = {"SECURE_CORE": 1, "TOR": 2, "P2P": 4, "XOR": 8, "IPV6": 16}
for _ in output:
    server_features_index = int(_["Features"])
    server_features  = []
    server_features_output = ""
    for f in all_features.keys():
        if (server_features_index & all_features[f]) > 0:
            server_features.append(f)
    if len(server_features) == 0:
        server_features_output = "None"
    else:
        server_features_output = ",".join(server_features)

    o = "{} {}@{}@{}@{}@{}@{}".format(_["Servers"][0]["ID"], _["Name"], \
      _["EntryCountry"], _["Load"], _["Servers"][0]["EntryIP"], _["Servers"][0]["ExitIP"], \
      str(server_features_output))
    print(o)
END`

  echo "$output"
}

function help_message() {
    echo
    echo -e "ProtonVPN Command-Line Tool\n"
    echo -e "Usage: $(basename $0) [option]\n"
    echo "Options:"
    echo "   --init                              Initialize ProtonVPN profile on the machine."
    echo "   -c, --connect                       Select and connect to a ProtonVPN server."
    echo "   -c [server-name] [protocol]         Connect to a ProtonVPN server by name."
    echo "   -r, --random-connect                Connect to a random ProtonVPN server."
    echo "   -f, --fastest-connect               Connect to the fastest available ProtonVPN server."
    echo "   -d, --disconnect                    Disconnect the current session."
    echo "   --ip                                Print the current public IP address."
    echo "   --update                            Update protonvpn-cli."
    echo "   --install                           Install protonvpn-cli."
    echo "   --uninstall                         Uninstall protonvpn-cli."
    echo "   -h, --help                          Show this help message."
    echo

    exit 0
}

check_requirements
user_input="$1"
case $user_input in
  ""|"-h"|"--help"|"--h"|"-help"|"help") help_message
    ;;
  "-d"|"--d"|"-disconnect"|"--disconnect") openvpn_disconnect
    ;;
  "-r"|"--r"|"-random"|"--random"|"-random-connect"|"--random-connect") connect_to_random_vpn
    ;;
  "-f"|"--f"|"-fastest"|"--fastest"|"-fastest-connect"|"--fastest-connect") connect_to_fastest_vpn
    ;;
  "-c"|"-connect"|"--c"|"--connect")
    if [[ $# == 1 ]]; then
      connection_to_vpn_via_dialog_menu
    elif [[ $# > 1 ]]; then
      connect_to_specific_server "$2" "$3"
    fi
    ;;
  "ip"|"-ip"|"--ip") check_ip
    ;;
  "update"|"-update"|"--update") update_cli
    ;;
  "-init"|"--init") init_cli
    ;;
  "-install"|"--install") install_cli
    ;;
  "-uninstall"|"--uninstall") uninstall_cli
    ;;
  *)
  echo "[!] Invalid input: $user_input"
  help_message
    ;;
esac
exit 0
