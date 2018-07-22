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
  if [[ -z $(which openvpn) ]]; then
    echo "[!] Error: openvpn is not installed. Install \`openvpn\` package to continue."
    exit 1
  fi

  if [[ ! -z $(which python) ]]; then
    python=$(which python)
  elif [[ ! -z $(which python3) ]]; then
    python=$(which python3)
  elif [[ ! -z $(which python2) ]]; then
    python=$(which python2)
  fi

  if [[ -z "$python" ]]; then
    echo "[!] Error: python is not installed. Install \`python\` package to continue."
    exit 1
  fi

  if [[ -z $(which dialog) ]]; then
    echo "[!] Error: dialog is not installed. Install \`dialog\` package to continue."
    exit 1
  fi
  if [[ -z $(which wget) ]]; then
    echo "[!] Error: wget is not installed. Install \`wget\` package to continue."
    exit 1
  fi

  if [[ -z $(which sysctl) && ( $(detect_platform_type) != "Mac" ) ]]; then
    echo "[!] Error: sysctl is not installed. Install \`sysctl\` package to continue."
    exit 1
  fi

  sha512sum_func
  if [[ -z "$sha512sum_tool" ]]; then
    echo "[!] Error: sha512sum is not installed. Install \`sha512sum\` package to continue."
    exit 1
  fi

  if [[ (! -x "/etc/openvpn/update-resolv-conf") && ( $(detect_platform_type) != "MacOS") ]]; then
    echo "[!] Error: update-resolv-conf is not installed."
    read -p "Would you like protonvpn-cli to install update-resolv-conf? (Y/N) (Default: N): " "user_confirm"
    if [[ "$user_confirm" == "Y" ]]; then
      install_update_resolv_conf
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

function sha512sum_func() {
  if [[ ! -z $(which sha512sum) ]]; then
    export sha512sum_tool="$(which sha512sum)"
  elif [[ ! -z $(which shasum) ]]; then
    export sha512sum_tool="$(which shasum) -a 512 "
  fi
}

function get_protonvpn_cli_home() {
  echo "$(get_home)/.protonvpn-cli"
}

function install_update_resolv_conf() {
  if [[ ("$UID" != 0) ]]; then
    echo "[!] Error: installation requires root access."
    exit 1
  fi
  echo "[*] Installing update-resolv-conf..."
  mkdir -p "/etc/openvpn/"
  file_sha512sum="81cf5ed20ec2a2f47f970bb0185fffb3e719181240f2ca3187dbee1f4d102ce63ab048ffee9daa6b68c96ac59d1d86ad4de2b1cfaf77f1b1f1918d143e96a588"
  wget "https://raw.githubusercontent.com/ProtonVPN/scripts/master/update-resolv-conf.sh" -O "/etc/openvpn/update-resolv-conf"
  if [[ ($? == 0) && ($($sha512sum_tool "/etc/openvpn/update-resolv-conf" | cut -d " " -f1) == "$file_sha512sum")  ]]; then
    chmod +x "/etc/openvpn/update-resolv-conf"
    echo "[*] Done."
  else
    echo "[!] Error installing update-resolv-conf."
    exit 1
  fi
}

function check_ip() {
  counter=0
  ip=""
  while [[ "$ip" == "" ]]; do
    if [[ $counter -lt 3 ]]; then
      ip=$(wget --header 'x-pm-appversion: Other' \
                --header 'x-pm-apiversion: 3' \
                --header 'Accept: application/vnd.protonmail.v1+json' \
                --timeout 4 --tries 1 -q -O - 'https://api.protonmail.ch/vpn/location' \
                | $python -c 'import json; _ = open("/dev/stdin", "r").read(); print(json.loads(_)["IP"])' 2> /dev/null)
      counter=$((counter+1))
    else
      ip="Error."
    fi
    if [[ -z "$ip" ]]; then
      sleep 2  # sleep for 2 seconds before retrying
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

function create_vi_bindings() {
    echo -en "
bindkey menubox \\j ITEM_NEXT
bindkey menubox \\k ITEM_PREV
bindkey menubox \\q ESC
bindkey menubox \\g PAGE_FIRST
bindkey menubox \\G PAGE_LAST
bindkey menubox \\l FIELD_NEXT
bindkey menubox \\h FIELD_NEXT
" > "$(get_protonvpn_cli_home)/.dialogrc"
}

function init_cli() {
  if [[ -f "$(get_protonvpn_cli_home)/protonvpn_openvpn_credentials" ]]; then
    echo -n "[!] user profile for protonvpn-cli has already been initialized. Would you like to start over with a fresh configuration? [Y/N] (Default: Y): "
    read "reset_profile"
  fi
  if  [[ ("$reset_profile" == "n" || "$reset_profile" == "N") ]]; then
     echo "[*] Profile initialization canceled."
     exit 0
  fi

  rm -rf "$(get_protonvpn_cli_home)/"  # Previous profile will be removed/overwritten, if any.
  mkdir -p "$(get_protonvpn_cli_home)/"

  create_vi_bindings

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

  read -p "Would you like to use a custom DNS server? (Warning: This would make your VPN connection vulnerable to DNS leaks. Only use it when you know what you're doing) [Y/N] (Default: N): " "use_custom_dns"

  if  [[ ("$use_custom_dns" == "y" || "$use_custom_dns" == "Y") ]]; then
     read -p "Custom DNS Server: " "custom_dns"
     echo -e "$custom_dns" > "$(get_protonvpn_cli_home)/.custom_dns"
     chown "$USER:$(id -gn $USER)" "$(get_protonvpn_cli_home)/.custom_dns"
     chmod 0400 "$(get_protonvpn_cli_home)/.custom_dns"
  fi

  chown -R "$USER:$(id -gn $USER)" "$(get_protonvpn_cli_home)/"
  chmod -R 0400 "$(get_protonvpn_cli_home)/"

  echo "[*] Done."
}

function detect_platform_type() {
  unameOut="$(uname -s)"
  case "${unameOut}" in
    Linux*)     platform=Linux;;
    Darwin*)    platform=MacOS;;
    CYGWIN*)    platform=Linux;;
    MINGW*)     platform=Linux;;
    *)          platform=Linux
  esac
  echo "$platform"
}

function manage_ipv6() {
  # ProtonVPN support for IPv6 coming soon.
  errors_counter=0
  if [[ ("$1" == "disable") && ( $(detect_platform_type) != "MacOS" ) ]]; then
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
  if [[ ("$1" == "disable") &&  ( $(detect_platform_type) == "MacOS" ) ]]; then
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

  if [[ ("$1" == "enable") && ( ! -f "$(get_protonvpn_cli_home)/.ipv6_address" ) && ( $(detect_platform_type) != "MacOS" ) ]]; then
    echo "[!] This is an error in enabling ipv6 on the machine. Please enable it manually."
  fi

  if [[ ("$1" == "enable") && ( -f "$(get_protonvpn_cli_home)/.ipv6_address" ) && ( $(detect_platform_type) != "MacOS" ) ]]; then
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

  if [[ ("$1" == "enable") && ( ! -f "$(get_protonvpn_cli_home)/.ipv6_services" ) && ( $(detect_platform_type) == "MacOS" ) ]]; then
    echo "[!] This is an error in enabling IPv6 on the machine. Please enable it manually."
  fi

  # Restore IPv6 in macOS.
  if [[ ("$1" == "enable") && ( -f "$(get_protonvpn_cli_home)/.ipv6_services" ) && ( $(detect_platform_type) == "MacOS" ) ]]; then
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
    echo "[!] There are issues in managing IPv6 in the system. Please test the system for the root cause."
    echo "Not being able to manage IPv6 by protonvpn-cli might cause issues in leaking the system's IPv6 address."
  fi
}

function modify_dns() {
  # Backup DNS entries
  if [[ ("$1" == "backup")]]; then
    if [[  ( $(detect_platform_type) == "MacOS" ) ]]; then
      networksetup listallnetworkservices | tail +2 | while read interface; do
        networksetup -getdnsservers "$interface" > "$(get_protonvpn_cli_home)/$interface.dns_backup"
      done
    else # non-Mac
      cp "/etc/resolv.conf" "/etc/resolv.conf.protonvpn_backup"
    fi
  fi

  # Apply ProtonVPN DNS
  if [[ ("$1" == "to_protonvpn_dns") ]]; then
      connection_logs="$(get_protonvpn_cli_home)/connection_logs"
      dns_server=$(cat "$connection_logs" | grep 'dhcp-option DNS' | head -n 1 | awk -F 'dhcp-option DNS ' '{print $2}' | cut -d ',' -f1) # protonvpn internal dns

    if [[ ( $(detect_platform_type) == "MacOS" ) ]]; then
      networksetup listallnetworkservices | tail +2 | while read interface; do
        networksetup -setdnsservers "$interface" $dns_server
      done
    else # non-Mac
      echo -e "# ProtonVPN DNS - protonvpn-cli\nnameserver $dns_server" > "/etc/resolv.conf"
    fi
  fi

  # Apply Custom DNS
  if [[ ("$1" == "to_custom_dns") ]]; then
      custom_dns="$(get_protonvpn_cli_home)/.custom_dns"
      dns_server=$(cat "$custom_dns")

    if [[ ( $(detect_platform_type) == "MacOS" ) ]]; then
      networksetup listallnetworkservices | tail +2 | while read interface; do
        networksetup -setdnsservers "$interface" $dns_server
      done
    else # non-Mac
      echo -e "# ProtonVPN DNS - Custom DNS\nnameserver $dns_server" > "/etc/resolv.conf"
    fi
  fi

  # Restore backed-up DNS entries
  if [[ "$1" == "revert_to_backup" ]]; then
    if [[  ( $(detect_platform_type) == "MacOS" )  ]]; then
      networksetup listallnetworkservices | tail +2 | while read interface; do
        file="$(get_protonvpn_cli_home)/$interface.dns_backup"
        if [[ -f "$file" ]]; then
          if grep -q "There aren't any DNS Servers set" "$file"; then
            networksetup -setdnsservers "$interface" empty
          else
            networksetup -setdnsservers "$interface" $(< $file)
          fi
        fi
      done
    else # non-Mac
      cp "/etc/resolv.conf.protonvpn_backup" "/etc/resolv.conf"
    fi
  fi
}

function is_internet_working_normally() {
  if [[ "$(check_ip)" != "Error." ]]; then
    echo true
  else
    echo false
  fi
}

function check_if_internet_is_working_normally() {
  if [[ "$(is_internet_working_normally)" == false ]]; then
    echo "[!] Error: There is an internet connection issue."
    exit 1
  fi
}

function is_openvpn_currently_running() {
  if [[ $(pgrep openvpn) == "" ]]; then
    echo false
  else
    echo true
  fi
}

function check_if_openvpn_is_currently_running() {
  if [[ $(is_openvpn_currently_running) == true ]]; then
    echo "[!] Error: OpenVPN is already running on this machine."
    exit 1
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

function openvpn_disconnect() {
  max_checks=3
  counter=0

  if [[ "$1" != "quiet" ]]; then
    echo "Disconnecting..."
  fi

  if [[ $(is_openvpn_currently_running) == true ]]; then
    manage_ipv6 enable # Enabling IPv6 on machine.
  fi

  while [[ $counter -lt $max_checks ]]; do
      pkill -f openvpn
      sleep 0.50
      if [[ $(is_openvpn_currently_running) == false ]]; then
        modify_dns revert_to_backup # Reverting to original DNS entries
        cp "$(get_protonvpn_cli_home)/.connection_config_id" "$(get_protonvpn_cli_home)/.previous_connection_config_id" 2> /dev/null
        cp "$(get_protonvpn_cli_home)/.connection_selected_protocol" "$(get_protonvpn_cli_home)/.previous_connection_selected_protocol" 2> /dev/null
        rm -f  "$(get_protonvpn_cli_home)/.connection_config_id" "$(get_protonvpn_cli_home)/.connection_selected_protocol" 2> /dev/null

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
  check_if_openvpn_is_currently_running

  modify_dns backup # Backing-up current DNS entries
  manage_ipv6 disable # Disabling IPv6 on machine.

  config_id=$1
  selected_protocol=$2
  if [[ -z "$selected_protocol" ]]; then
    selected_protocol="udp"  # Default protocol
  fi

  current_ip="$(check_ip)"
  connection_logs="$(get_protonvpn_cli_home)/connection_logs"

  rm -f "$connection_logs"  # Remove previous connection logs

  if [[ "$PROTONVPN_CLI_LOG" == "true" ]]; then  # PROTONVPN_CLI_LOG is retrieved from env.
    # This option only prints the path of connection_logs to end-user
    echo "[*] CLI logging mode enabled."
    echo -e "[*] Logs path: $connection_logs"
  fi

      wget --header 'x-pm-appversion: Other' \
         --header 'x-pm-apiversion: 3' \
         --header 'Accept: application/vnd.protonmail.v1+json' \
         --timeout 10 --tries 1 -q -O - "https://api.protonmail.ch/vpn/config?Platform=$(detect_platform_type)&LogicalID=$config_id&Protocol=$selected_protocol" \
         | openvpn --daemon --config "/dev/stdin" --auth-user-pass "$(get_protonvpn_cli_home)/protonvpn_openvpn_credentials" --auth-retry nointeract --verb 4 --log "$connection_logs"

  echo "Connecting..."

  max_checks=3
  counter=0
  while [[ $counter -lt $max_checks ]]; do
    sleep 6
    new_ip="$(check_ip)"
    if [[ ("$current_ip" != "$new_ip") && ("$new_ip" != "Error.") ]]; then
      echo "[$] Connected!"
      echo "[#] New IP: $new_ip"

        # DNS management
        if [[ -f "$(get_protonvpn_cli_home)/.custom_dns" ]]; then
          modify_dns to_custom_dns # Use Custom DNS
          echo "[Warning] You have chosen to use a custom DNS server. This may make you vulnerable to DNS leaks. Re-initialize your profile to disable the use of custom DNS."
        else
          modify_dns to_protonvpn_dns # Use protonvpn DNS server
        fi
      echo "$config_id" > "$(get_protonvpn_cli_home)/.connection_config_id"
      echo "$selected_protocol" > "$(get_protonvpn_cli_home)/.connection_selected_protocol"
      exit 0
    fi

    counter=$((counter+1))
  done

  echo "[!] Error connecting to VPN."
  if [[ ! -z $(cat "$connection_logs" | grep "AUTH_FAILED") ]]; then
    echo "[!] Reason: Authentication Failed. Please check you ProtonVPN OpenVPN credentials."
  fi
  openvpn_disconnect quiet
  exit 1
}

function update_cli() {
  check_if_internet_is_working_normally

  cli_path="/usr/local/bin/protonvpn-cli"
  if [[ ! -f "$cli_path" ]]; then
    echo "[!] Error: protonvpn-cli does not seem to be installed."
    exit 1
  fi
  echo "[#] Checking for update."
  current_local_hashsum=$($sha512sum_tool "$cli_path" | cut -d " " -f1)
  remote_=$(wget --timeout 6 -q -O - 'https://raw.githubusercontent.com/ProtonVPN/protonvpn-cli/master/protonvpn-cli.sh')
  if [[ $? != 0 ]]; then
    echo "[!] Error: There is an error updating protonvpn-cli."
    exit 1
  fi
  remote_hashsum=$(echo "$remote_" | $sha512sum_tool | cut -d ' ' -f1)

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
  cli="$(cd "$(dirname "$0")"; pwd -P)/$0"
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

  if [[ ($errors_counter == 0) || ( ! -z $(which protonvpn-cli) ) ]]; then
    echo "[*] Done."
    exit 0
  else
    echo "[!] Error: There was an error in installing protonvpn-cli."
    exit 1
  fi
}

function uninstall_cli() {

  if [[ $(is_openvpn_currently_running) == true ]]; then
    echo "[!] OpenVPN is currently running."
    echo "[!] Session will be disconnected."
    openvpn_disconnect quiet dont_exit
    if [[ $(is_openvpn_currently_running) == true ]]; then  # checking if it OpenVPN is still active.
      echo "[!] Error disconnecting OpenVPN."
      echo "[!] Please disconnect manually and try the uninstallation again."
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
    exit 0
  else
    echo "[!] Error: There was an error in uninstalling protonvpn-cli."
    exit 1
  fi
}

function print_console_status() {
  current_ip="$(check_ip)"
  if [[ $(is_openvpn_currently_running) == true ]]; then
    echo "[OpenVPN Status]: Running"
  else
    echo "[OpenVPN Status]: Not Running"
  fi

  if [[ -f "$(get_protonvpn_cli_home)/.connection_config_id" ]]; then
    echo "[ProtonVPN Status]: Running"
  else
    echo "[ProtonVPN Status]: Not Running"
  fi

  if [[ "$current_ip" == "Error." ]]; then
    echo "[Internet Status]: Offline"
    exit 0
  else
    echo "[Internet Status]: Online"
    echo "[Public IP Address]: $current_ip"
  fi
  if [[ -f "$(get_protonvpn_cli_home)/.connection_config_id" ]]; then
    config_id=$(cat "$(get_protonvpn_cli_home)/.connection_config_id")
    vpn_server_details=$(get_vpn_server_details "$config_id")
    server_name=$(echo "$vpn_server_details" | cut -d '@' -f1)
    server_exit_country=$(echo "$vpn_server_details" | cut -d '@' -f2)
    server_tier=$(echo "$vpn_server_details" | cut -d '@' -f3)
    server_features=$(echo "$vpn_server_details" | cut -d '@' -f4)
    server_load=$(echo "$vpn_server_details" | cut -d '@' -f5)
    selected_protocol=$(cat "$(get_protonvpn_cli_home)/.connection_selected_protocol" | tr '[:lower:]' '[:upper:]')

    echo "[ProtonVPN] [Server Name]: $server_name"
    echo "[ProtonVPN] [OpenVPN Protocol]: $selected_protocol"
    echo "[ProtonVPN] [Exit Country]: $server_exit_country"
    echo "[ProtonVPN] [Tier]: $server_tier"
    echo "[ProtonVPN] [Server Features]: $server_features"
    echo "[ProtonVPN] [Server Load]: $server_load"

  fi
    exit 0

}

function connect_to_fastest_vpn() {
  check_if_profile_initialized
  check_if_openvpn_is_currently_running
  check_if_internet_is_working_normally

  echo "Fetching ProtonVPN Servers..."
  config_id=$(get_fastest_vpn_connection_id)
  selected_protocol="udp"
  openvpn_connect "$config_id" "$selected_protocol"
}

function connect_to_fastest_p2p_vpn() {
  check_if_profile_initialized
  check_if_openvpn_is_currently_running
  check_if_internet_is_working_normally

  echo "Fetching ProtonVPN Servers..."
  config_id=$(get_fastest_vpn_connection_id "P2P")
  selected_protocol="udp"
  openvpn_connect "$config_id" "$selected_protocol"
}

function connect_to_random_vpn() {
  check_if_profile_initialized
  check_if_openvpn_is_currently_running
  check_if_internet_is_working_normally

  echo "Fetching ProtonVPN Servers..."
  config_id=$(get_random_vpn_connection_id)
  available_protocols=("tcp" "udp")
  selected_protocol=${available_protocols[$RANDOM % ${#available_protocols[@]}]}
  openvpn_connect "$config_id" "$selected_protocol"
}

function connect_to_previous_vpn() {
  check_if_profile_initialized
  check_if_openvpn_is_currently_running
  check_if_internet_is_working_normally

  if ! [[ -f "$(get_protonvpn_cli_home)/.previous_connection_config_id" && \
          -f "$(get_protonvpn_cli_home)/.previous_connection_selected_protocol" ]]; then
    echo "[!] No previous VPN server were found."
    exit 1
  fi

  config_id=$(cat "$(get_protonvpn_cli_home)/.previous_connection_config_id")
  selected_protocol=$(cat "$(get_protonvpn_cli_home)/.previous_connection_selected_protocol")
  openvpn_connect "$config_id" "$selected_protocol"
}

function reconnect_to_current_vpn() {
  check_if_profile_initialized

  if [[ ($(is_openvpn_currently_running) == false) || (! -f "$(get_protonvpn_cli_home)/.connection_config_id") ]] ; then
    echo "[!] Error: ProtonVPN is not currently running."
    exit 1
  fi

  openvpn_disconnect "quiet" "dont_exit"
  if [[ $(is_openvpn_currently_running) == true ]]; then  # checking if it OpenVPN is still active.
    echo "[!] Error disconnecting OpenVPN."
    exit 1
  else
    echo "[#] Disconnected."
  fi
  echo "Reconnecting..."
  connect_to_previous_vpn
}


function connect_to_specific_server() {
  check_if_profile_initialized
  check_if_openvpn_is_currently_running
  check_if_internet_is_working_normally

  echo "Fetching ProtonVPN Servers..."

  if [[ "$3" == "server" ]]; then
    server_list=$(get_vpn_config_details | tr ' ' '@')
  fi

  if [[ "$3" == "country" ]]; then
    server_list=$(get_country_vpn_servers_details | tr ' ' '@')
  fi

  if [[ "$(echo "$2" | tr '[:upper:]' '[:lower:]')" == "tcp" ]]; then
    protocol="tcp"
  else
    protocol="udp"
  fi

  if [[ "$3" == "server" ]]; then
    for i in $server_list; do
      id=$(echo "$i" | cut -d"@" -f1)
      name=$(echo "$i" | cut -d"@" -f2)
      if [[ "$(echo "$1" | tr '[:upper:]' '[:lower:]')" == "$(echo "$name" | tr '[:upper:]' '[:lower:]')"  ]]; then
        openvpn_connect "$id" "$protocol"
      fi
    done
  fi

  if [[ "$3" == "country" ]]; then
    for i in $server_list; do
      id=$(echo "$i" | cut -d"@" -f1)
      name=$(echo "$i" | cut -d"@" -f2)
      country=$(echo "$i" | cut -d"@" -f3)
      if [[ "$(echo "$1" | tr '[:upper:]' '[:lower:]')" == "$(echo "$country" | tr '[:upper:]' '[:lower:]')"  ]]; then
        openvpn_connect "$id" "$protocol"
      fi
    done
  fi

  # If not found in $server_list.
  if [[ "$3" == "server" ]]; then
    echo "[!] Error: Invalid server name, or server not accessible with your plan."
  fi
  if [[ "$3" == "country" ]]; then
    echo "[!] Error: Invalid country name, or country not accessible with your plan."
  fi
  exit 1
}

function connection_to_vpn_via_dialog_menu() {
  check_if_profile_initialized
  check_if_openvpn_is_currently_running
  check_if_internet_is_working_normally

  available_protocols=("udp" " " "tcp" " ")
  IFS=$'\n'
  ARRAY=()

  echo "Fetching ProtonVPN Servers..."

  if [[ "$1" == "servers" ]]; then
    c2=$(get_vpn_config_details)
  fi
  if [[ "$1" == "countries" ]]; then
    c2=$(get_country_vpn_servers_details)
  fi

  counter=0
  for i in $c2; do
    ID=$(echo "$i" | cut -d " " -f1)
    data=$(echo "$i" | tr '@' ' ' | awk '{$1=""; print $0}' | tr ' ' '@')
    counter=$((counter+1))
    ARRAY+=($counter)
    ARRAY+=($data)
  done

  # Set DIALOGRC to a custom file including VI key binding
  if [[ -f "$(get_protonvpn_cli_home)/.dialogrc" ]]; then
      export DIALOGRC="$(get_protonvpn_cli_home)/.dialogrc"
  fi

  config_id=$(dialog --clear  --ascii-lines --output-fd 1 --title "ProtonVPN-CLI" --column-separator "@" \
    --menu "ID - Name - Country - Load - EntryIP - ExitIP - Features" 35 300 "$((${#ARRAY[@]}))" "${ARRAY[@]}" )
  clear
  if [[ -z "$config_id" ]]; then
    exit 1
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
  if [[ -z "$selected_protocol" ]]; then
    exit 1
  fi

  openvpn_connect "$config_id" "$selected_protocol"

}

function get_vpn_server_details() {
  response_cache_path="$(get_protonvpn_cli_home)/.response_cache"
  config_id="$1"
  output=`$python <<END
import json
response_cache = open("""$response_cache_path""", "r").read()
json_parsed_response = json.loads(response_cache)

output = ""
all_features = {"SECURE_CORE": 1, "TOR": 2, "P2P": 4, "XOR": 8, "IPV6": 16}
server_features = []
for _ in json_parsed_response["LogicalServers"]:
    if ("""$config_id""" == _["ID"]):
        server_features_index = int(_["Features"])
        for f in all_features.keys():
            if (server_features_index & all_features[f]) > 0:
                server_features.append(f)
        if len(server_features) == 0:
            server_features_value = "None"
        else:
            server_features_value = ", ".join(server_features)
        output = "%s@%s@%s@%s@%s"%(_["Name"], _["ExitCountry"], _["Tier"], server_features_value, _["Load"])
        break
print(output)
END`

  echo "$output"

}

function get_country_vpn_servers_details() {
  response_output=$(wget --header 'x-pm-appversion: Other' \
                         --header 'x-pm-apiversion: 3' \
                         --header 'Accept: application/vnd.protonmail.v1+json' \
                         --timeout 20 --tries 1 -q -O - "https://api.protonmail.ch/vpn/logicals" | tee $(get_protonvpn_cli_home)/.response_cache)
  tier=$(cat "$(get_protonvpn_cli_home)/protonvpn_tier")
  user_chosen_specific_country="$1"
  output=`python <<END
import json
json_parsed_response = json.loads("""$response_output""")
output = []
all_features = {"SECURE_CORE": 1, "TOR": 2, "P2P": 4, "XOR": 8, "IPV6": 16}
excluded_features_on_fastest_connect = ["TOR"]

for _ in json_parsed_response["LogicalServers"]:
    if (_["Tier"] <= int("""$tier""")):
        output.append(_)

candidates_1 = {}
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

  is_excluded = False
  for excluded_feature in excluded_features_on_fastest_connect:
      if excluded_feature in server_features:
          is_excluded = True
  if is_excluded is True:
      continue

  if _["ExitCountry"] not in candidates_1.keys():
      candidates_1.update({_["ExitCountry"]: [_]})
  else:
      candidates_1[_["ExitCountry"]].append(_)

candidates_2 = {}
for country in candidates_1.keys():
    candidates_2.update({country: candidates_1[country][0]})

    for server in candidates_1[country]:
        if server["Score"] < candidates_2[country]["Score"]:
            candidates_2.update({country: server})

for _ in candidates_2.keys():
  o = "{} {}@{}@{}@{}@{}@{}".format(candidates_2[_]["ID"], candidates_2[_]["Name"], \
  candidates_2[_]["ExitCountry"], candidates_2[_]["Load"], candidates_2[_]["Servers"][0]["EntryIP"], candidates_2[_]["Servers"][0]["ExitIP"], \
  str(server_features_output))

  print(o)
END`

  echo "$output"
}

function get_fastest_vpn_connection_id() {
  required_feature=${1:-}
  response_output=$(wget --header 'x-pm-appversion: Other' \
                         --header 'x-pm-apiversion: 3' \
                         --header 'Accept: application/vnd.protonmail.v1+json' \
                         --timeout 20 --tries 1 -q -O - "https://api.protonmail.ch/vpn/logicals" | tee $(get_protonvpn_cli_home)/.response_cache)
  tier=$(cat "$(get_protonvpn_cli_home)/protonvpn_tier")
  output=`$python <<END
import json, math, random
json_parsed_response = json.loads("""$response_output""")

all_features = {"SECURE_CORE": 1, "TOR": 2, "P2P": 4, "XOR": 8, "IPV6": 16}
excluded_features_on_fastest_connect = ["TOR"]
required_features = ["$required_feature"] if "$required_feature" in all_features else []

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
    for required_feature in required_features:
        if required_feature not in server_features:
            is_excluded = True
    if is_excluded is True:
        continue
    if (_["Tier"] <= int("""$tier""")):
        candidates_1.append(_)

candidates_2_size = float(len(candidates_1)) / 100.00 * 5.00
candidates_2 = sorted(candidates_1, key=lambda l: l["Score"])[:int(math.ceil(candidates_2_size))]
random_candidate = random.choice(candidates_2)
vpn_connection_id = random_candidate["ID"]
print(vpn_connection_id)

END`

  echo "$output"
}

function get_random_vpn_connection_id() {
  response_output=$(wget --header 'x-pm-appversion: Other' \
                         --header 'x-pm-apiversion: 3' \
                         --header 'Accept: application/vnd.protonmail.v1+json' \
                         --timeout 20 --tries 1 -q -O - "https://api.protonmail.ch/vpn/logicals" | tee $(get_protonvpn_cli_home)/.response_cache)
  tier=$(cat "$(get_protonvpn_cli_home)/protonvpn_tier")
  output=`$python <<END
import json, random
json_parsed_response = json.loads("""$response_output""")
output = []
for _ in json_parsed_response["LogicalServers"]:
    if (_["Tier"] <= int("""$tier""")):
        output.append(_)
print(random.choice(output)["ID"])
END`

  echo "$output"
}

function get_vpn_tier() {
  response_cache_path="$(get_protonvpn_cli_home)/.response_cache"
  output=`$python <<END
import json
response_cache_fileread = open("""$response_cache_path""", "r").read()
json_parsed_response = json.loads(response_cache_fileread)
for _ in json_parsed_response["LogicalServers"]:
    if (_["ID"] == """$1"""):
        print(_["Tier"])
        break
END`

  echo "$output"
}

function get_vpn_config_details() {
  response_output=$(wget --header 'x-pm-appversion: Other' \
                         --header 'x-pm-apiversion: 3' \
                         --header 'Accept: application/vnd.protonmail.v1+json' \
                         --timeout 20 --tries 1 -q -O - "https://api.protonmail.ch/vpn/logicals" | tee $(get_protonvpn_cli_home)/.response_cache)
  tier=$(cat "$(get_protonvpn_cli_home)/protonvpn_tier")
  output=`$python <<END
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

    o = "{} {}@{}@{}@{}@{}@{}".format(_["ID"], _["Name"], \
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
    echo "   -l, --last-connect                  Connect to the previously used ProtonVPN server."
    echo "   -f, --fastest-connect               Connect to the fastest available ProtonVPN server."
    echo "   -p2p, --p2p-connect                 Connect to the fastest available P2P ProtonVPN server."
    echo "   -cc, --country-connect              Select and connect to a ProtonVPN server by country."
    echo "   -cc [country-name] [protocol]       Connect to the fastest available server in a specific country."
    echo "   -d, --disconnect                    Disconnect the current session."
    echo "   --reconnect                         Reconnect to the current server."
    echo "   --ip                                Print the current public IP address."
    echo "   --status                            Print connection status."
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
  "-reconnect"|"--reconnect") reconnect_to_current_vpn
    ;;
  "-r"|"--r"|"-random"|"--random"|"-random-connect"|"--random-connect") connect_to_random_vpn
    ;;
  "-l"|"--l"|"-last-connect"|"--last-connect") connect_to_previous_vpn
    ;;
  "-f"|"--f"|"-fastest"|"--fastest"|"-fastest-connect"|"--fastest-connect") connect_to_fastest_vpn
    ;;
  "-p2p"|"--p2p"|"-p2p-connect"|"--p2p-connect") connect_to_fastest_p2p_vpn
    ;;
    "-cc"|"--cc"|"-country-connect"|"--country-connect")
    if [[ $# == 1 ]]; then
      connection_to_vpn_via_dialog_menu "countries"
    elif [[ $# > 1 ]]; then
      connect_to_specific_server "$2" "$3" "country"
    fi
    ;;
  "-c"|"-connect"|"--c"|"--connect")
    if [[ $# == 1 ]]; then
      connection_to_vpn_via_dialog_menu "servers"
    elif [[ $# > 1 ]]; then
      connect_to_specific_server "$2" "$3" "server"
    fi
    ;;
  "ip"|"-ip"|"--ip") check_ip
    ;;
    "status"|"-status"|"--status") print_console_status
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
