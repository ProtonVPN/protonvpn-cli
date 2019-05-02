#!/usr/bin/env bash
######################################################
# ProtonVPN CLI
# ProtonVPN Command-Line Tool
#
# Made with <3 for Linux + macOS.
###
#Author: Mazin Ahmed <Mazin AT ProtonMail DOT ch>
######################################################
version=1.1.2

if [[ ("$UID" != 0) && ("$1" != "ip") && ("$1" != "-ip") && \
      ("$1" != "--ip") && ! (-z "$1") && ("$1" != "-h") && \
      ("$1" != "--status") && ("$1" != "-status") && ("$1" != "status") && \
      ("$1" != "--help") && ("$1" != "--h") && ("$1" != "-help") && \
      ("$1" != "help") && ("$1" != "--version") && ("$1" != "-version") && \
      ("$1" != "-v") && ("$1" != "--v")]]; then
  echo "[!] Error: The program requires root access."
  exit 1
fi

function check_requirements() {
  if [[ -z $(which openvpn) ]]; then
    echo "[!] Error: openvpn is not installed. Install \`openvpn\` package to continue."
    exit 1
  fi

  if [[ -n $(which python) ]]; then
    python=$(which python)
  elif [[ -n $(which python3) ]]; then
    python=$(which python3)
  elif [[ -n $(which python2) ]]; then
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

  if [[ -z $(which sysctl) && ( $(detect_platform_type) != "macos" ) ]]; then
    echo "[!] Error: sysctl is not installed. Install \`sysctl\` package to continue."
    exit 1
  fi

  if [[ $(detect_platform_type) != "macos" ]]; then
    if [[ ( -z $(which iptables) ) ||  ( -z $(which iptables-save) ) || ( -z $(which iptables-restore) ) ]]; then
      echo "[!] Error: iptables is not installed. Install \`iptables\` package to continue."
      exit 1
    fi
  fi

  sha512sum_func
  if [[ -z "$sha512sum_tool" ]]; then
    echo "[!] Error: sha512sum is not installed. Install \`sha512sum\` package to continue."
    exit 1
  fi

  if [[ (! -x "/etc/openvpn/update-resolv-conf") && ( $(detect_platform_type) != "macos") ]]; then
    echo "[!] Error: update-resolv-conf is not installed."
    read -p "Would you like protonvpn-cli to install update-resolv-conf? (y/N): " "user_confirm"
    if [[ "$user_confirm" == "y" || "$user_confirm" == "Y" ]]; then
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
  if [[ -n $(which sha512sum) ]]; then
    sha512sum_tool="$(which sha512sum)"
  elif [[ -n $(which shasum) ]]; then
    sha512sum_tool="$(which shasum) -a 512 "
  fi
  export sha512sum_tool
}

function get_protonvpn_cli_home() {
  echo "$(get_home)/.protonvpn-cli"
}

function install_update_resolv_conf() {
  if [[ ("$UID" != 0) ]]; then
    echo "[!] Error: Installation requires root access."
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
    rm -f "/etc/openvpn/update-resolv-conf" 2> /dev/null
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
                -o /dev/null \
                --timeout 6 --tries 1 -q -O - 'https://api.protonmail.ch/vpn/location' \
                | $python -c 'import json; _ = open("/dev/stdin", "r").read(); print(json.loads(_)["IP"])' 2> /dev/null)
      counter=$((counter+1))
    else
      ip="Error."
    fi
    if [[ -z "$ip" ]]; then
      sleep 2  # Sleep for 2 seconds before retrying.
    fi
  done
  echo "$ip"
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
    echo -n "[!] User profile for protonvpn-cli has already been initialized. Would you like to start over with a fresh configuration? [Y/n]: "
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

  read -p "[.] Would you like to use a custom DNS server? (Warning: This would make your VPN connection vulnerable to DNS leaks. Only use it when you know what you're doing) [y/N]: " "use_custom_dns"

  if  [[ ("$use_custom_dns" == "y" || "$use_custom_dns" == "Y") ]]; then
     custom_dns=""
     while [[ $custom_dns == "" ]]; do
       read -p "Custom DNS Server: " "custom_dns"
     done
     echo -e "$custom_dns" > "$(get_protonvpn_cli_home)/.custom_dns"
     chown "$USER:$(id -gn $USER)" "$(get_protonvpn_cli_home)/.custom_dns"
     chmod 0400 "$(get_protonvpn_cli_home)/.custom_dns"
  fi

  read -p "[.] [Security] Decrease OpenVPN privileges? [Y/n]: " "decrease_openvpn_privileges"
  if [[ "$decrease_openvpn_privileges" == "y" || "$decrease_openvpn_privileges" == "Y" ||  "$decrease_openvpn_privileges" == "" ]]; then
    echo "$decrease_openvpn_privileges" > "$(get_protonvpn_cli_home)/.decrease_openvpn_privileges"
  fi

  # Disabling killswitch prompt
  #read -p "[.] Enable Killswitch? [Y/n]: " "enable_killswitch"
  #if [[ "$enable_killswitch" == "y" || "$enable_killswitch" == "Y" || "$enable_killswitch" == "" ]]; then
  #  echo > "$(get_protonvpn_cli_home)/.enable_killswitch"
  #fi

  config_cache_path="$(get_protonvpn_cli_home)/openvpn_cache/"
  rm -rf "$config_cache_path"
  mkdir -p "$config_cache_path"  # Folder for openvpn config cache.

  chown -R "$USER:$(id -gn $USER)" "$(get_protonvpn_cli_home)/"
  chmod -R 0400 "$(get_protonvpn_cli_home)/"

  echo "[*] Done."
}

function detect_platform_type() {
  unameOut="$(uname -s)"
  case "${unameOut}" in
    Linux*)     platform=linux;;
    Darwin*)    platform=macos;;
    CYGWIN*)    platform=linux;;
    MINGW*)     platform=linux;;
    *)          platform=linux
  esac
  echo "$platform"
}

function manage_ipv6() {
  # ProtonVPN support for IPv6 coming soon.
  errors_counter=0
  if [[ ("$1" == "disable") && ( $(detect_platform_type) != "macos" ) ]]; then
    if [ -n "$(ip -6 a 2> /dev/null)" ]; then

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
  if [[ ("$1" == "disable") &&  ( $(detect_platform_type) == "macos" ) ]]; then
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

  if [[ ("$1" == "enable") && ( ! -f "$(get_protonvpn_cli_home)/.ipv6_address" ) && ( $(detect_platform_type) != "macos" ) ]]; then
    echo "[!] This is an error in enabling IPv6 on the machine. Please enable it manually."
  fi

  if [[ ("$1" == "enable") && ( -f "$(get_protonvpn_cli_home)/.ipv6_address" ) && ( $(detect_platform_type) != "macos" ) ]]; then
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

  if [[ ("$1" == "enable") && ( ! -f "$(get_protonvpn_cli_home)/.ipv6_services" ) && ( $(detect_platform_type) == "macos" ) ]]; then
    echo "[!] This is an error in enabling IPv6 on the machine. Please enable it manually."
  fi

  # Restore IPv6 in macOS.
  if [[ ("$1" == "enable") && ( -f "$(get_protonvpn_cli_home)/.ipv6_services" ) && ( $(detect_platform_type) == "macos" ) ]]; then
    if [[ $(< "$(get_protonvpn_cli_home)/.ipv6_services") == "" ]] ; then
      return
    fi

    ipv6_service=$(< "$(get_protonvpn_cli_home)/.ipv6_services")

    while read ipv6_service ; do
      networksetup -setv6automatic "$ipv6_service"
    done < "$(get_protonvpn_cli_home)/.ipv6_services"

    rm -f "$(get_protonvpn_cli_home)/.ipv6_services"
  fi

  if [[ $errors_counter != 0 ]]; then
    echo "[!] There are issues in managing IPv6 in the system. Please test the system for the root cause."
    echo "Not being able to manage IPv6 by protonvpn-cli may leak the system's IPv6 address."
  fi
}

function sanitize_interface_name() {
  echo "$1" | sed 's/[^a-zA-Z0-9_-]/_/g'
}

function modify_dns() {
  # Backup DNS entries.
  if [[ ("$1" == "backup") ]]; then
    if [[  ( $(detect_platform_type) == "macos" ) ]]; then
      networksetup listallnetworkservices | tail +2 | while read interface; do
        networksetup -getdnsservers "$interface" > "$(get_protonvpn_cli_home)/$(sanitize_interface_name "$interface").dns_backup"
      done
    else # non-Mac
      cp "/etc/resolv.conf" "$(get_protonvpn_cli_home)/.resolv.conf.protonvpn_backup"
    fi
  fi

  # Apply ProtonVPN DNS.
  if [[ ("$1" == "to_protonvpn_dns") ]]; then
      connection_logs="$(get_protonvpn_cli_home)/connection_logs"
      dns_server=$(grep 'dhcp-option DNS' "$connection_logs" | head -n 1 | awk -F 'dhcp-option DNS ' '{print $2}' | cut -d ',' -f1) # ProtonVPN internal DNS.

    if [[ ( $(detect_platform_type) == "macos" ) ]]; then
      networksetup listallnetworkservices | tail +2 | while read interface; do
        networksetup -setdnsservers "$interface" $dns_server
      done
    else # non-Mac
      echo -e "# ProtonVPN DNS - protonvpn-cli\nnameserver $dns_server" > "/etc/resolv.conf"
    fi
  fi

  # Apply Custom DNS.
  if [[ ("$1" == "to_custom_dns") ]]; then
      custom_dns="$(get_protonvpn_cli_home)/.custom_dns"
      dns_server=$(< "$custom_dns")

    if [[ ( $(detect_platform_type) == "macos" ) ]]; then
      networksetup listallnetworkservices | tail +2 | while read interface; do
        networksetup -setdnsservers "$interface" $dns_server
      done
    else # non-Mac
      echo -e "# ProtonVPN DNS - Custom DNS\nnameserver $dns_server" > "/etc/resolv.conf"
    fi
  fi

  # Restore backed-up DNS entries.
  if [[ "$1" == "revert_to_backup" ]]; then
    if [[  ( $(detect_platform_type) == "macos" )  ]]; then
      networksetup listallnetworkservices | tail +2 | while read interface; do
        file="$(get_protonvpn_cli_home)/$(sanitize_interface_name "$interface").dns_backup"
        if [[ -f "$file" ]]; then
          if grep -q "There aren't any DNS Servers set" "$file"; then
            networksetup -setdnsservers "$interface" empty
          else
            networksetup -setdnsservers "$interface" "$(< "$file")"
          fi
        fi
      done
    else # non-Mac
      cp "$(get_protonvpn_cli_home)/.resolv.conf.protonvpn_backup" "/etc/resolv.conf"
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
  disconnected=false

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
        disconnected=true
        # killswitch disable # Disabling killswitch
        cp "$(get_protonvpn_cli_home)/.connection_config_id" "$(get_protonvpn_cli_home)/.previous_connection_config_id" 2> /dev/null
        cp "$(get_protonvpn_cli_home)/.connection_selected_protocol" "$(get_protonvpn_cli_home)/.previous_connection_selected_protocol" 2> /dev/null
        rm -f  "$(get_protonvpn_cli_home)/.connection_config_id" "$(get_protonvpn_cli_home)/.connection_selected_protocol" 2> /dev/null

        if [[ "$1" != "quiet" ]]; then
          echo "[#] Disconnected."
          echo "[#] Current IP: $(check_ip)"
        fi

        if [[ "$2" != "dont_exit" ]]; then
          exit 0
        else
          break
        fi
      fi
    counter=$((counter+1))
  done

  if [[ "$disconnected" == false ]]; then
    if [[ "$1" != "quiet" ]]; then
      echo "[!] Error disconnecting OpenVPN."

      if [[ "$2" != "dont_exit" ]]; then
        exit 1
      fi

    fi
  fi
}

function openvpn_connect() {
  check_if_openvpn_is_currently_running

  modify_dns backup # Backing-up current DNS entries.
  manage_ipv6 disable # Disabling IPv6 on machine.
  # killswitch backup_rules # Backing-up firewall rules.

  config_id=$1
  selected_protocol=$2
  if [[ -z "$selected_protocol" ]]; then
    selected_protocol="udp"  # Default protocol
  fi

  current_ip="$(check_ip)"
  connection_logs="$(get_protonvpn_cli_home)/connection_logs"
  openvpn_config="$(get_protonvpn_cli_home)/protonvpn_openvpn_config.conf"

  rm -f "$connection_logs"  # Remove previous connection logs.
  rm -f "$openvpn_config" # Remove previous openvpn config.

  config_cache_path="$(get_protonvpn_cli_home)/openvpn_cache/"
  mkdir -p "$config_cache_path"  # Folder for openvpn config cache.

  if [[ "$PROTONVPN_CLI_LOG" == "true" ]]; then  # PROTONVPN_CLI_LOG is retrieved from env.
    # This option only prints the path of connection_logs to end-user.
    echo "[*] CLI logging mode enabled."
    echo -e "[*] Logs path: $connection_logs"
  fi

  # Set PROTONVPN_CLI_DAEMON=false to disable daemonization of openvpn.
  PROTONVPN_CLI_DAEMON=${PROTONVPN_CLI_DAEMON:=true}

  wget \
    --header 'x-pm-appversion: Other' \
    --header 'x-pm-apiversion: 3' \
    --header 'Accept: application/vnd.protonmail.v1+json' \
    -o /dev/null \
    --timeout 10 --tries 1 -q -O "$openvpn_config" \
    "https://api.protonmail.ch/vpn/config?Platform=$(detect_platform_type)&LogicalID=$config_id&Protocol=$selected_protocol"

  config_cache_name="$config_cache_path/$(detect_platform_type)-$config_id-$selected_protocol"
  if [[ -f "$config_cache_name" ]]; then
    if [[ $(diff "$config_cache_name" "$openvpn_config") ]]; then
      echo "Configuration changed (of $(detect_platform_type)-$selected_protocol-$config_id)"
    fi
  fi

  cp "$openvpn_config" "$config_cache_name"
  echo "Connecting..."
  {
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
          modify_dns to_custom_dns # Use Custom DNS.
          echo "[Warning] You have chosen to use a custom DNS server. This may make you vulnerable to DNS leaks. Re-initialize your profile to disable the use of custom DNS."
        else
          modify_dns to_protonvpn_dns # Use ProtonVPN DNS server.
        fi

        # killswitch enable # Enable killswitch

        echo "$config_id" > "$(get_protonvpn_cli_home)/.connection_config_id"
        echo "$selected_protocol" > "$(get_protonvpn_cli_home)/.connection_selected_protocol"
        exit 0
      fi

      counter=$((counter+1))
    done

    echo "[!] Error connecting to VPN."
    if grep -q "AUTH_FAILED" "$connection_logs"; then
      echo "[!] Reason: Authentication failed. Please check your ProtonVPN OpenVPN credentials."
    fi
    openvpn_disconnect quiet dont_exit
    exit 1
  } &
  status_check_pid=$!

  OPENVPN_OPTS=(
    --config "$openvpn_config"
    --auth-user-pass "$(get_protonvpn_cli_home)/protonvpn_openvpn_credentials"
    --auth-retry nointeract
    --verb 4
    --log "$connection_logs"
  )

  if [[ -f "$(get_protonvpn_cli_home)/.decrease_openvpn_privileges" ]]; then
    OPENVPN_OPTS+=(--user nobody
                   --group "$(id -gn nobody)"
                  )
  fi

  if [[ $PROTONVPN_CLI_DAEMON == true ]]; then
    openvpn --daemon "${OPENVPN_OPTS[@]}"
    trap 'openvpn_disconnect "" dont_exit' INT TERM
  else
    trap 'openvpn_disconnect "" dont_exit' INT TERM
    openvpn "${OPENVPN_OPTS[@]}"
    openvpn_exit=$?
  fi

  wait $status_check_pid
  status_exit=$?
  if [[ $PROTONVPN_CLI_DAEMON != true ]] && (( status_exit == 0 )); then
    status_exit=$openvpn_exit
  fi
  exit $status_exit
}

function update_cli() {
  check_if_internet_is_working_normally

  cli_path="/usr/local/bin/protonvpn-cli"
  if [[ ! -f "$cli_path" ]]; then
    echo "[!] Error: protonvpn-cli does not seem to be installed."
    exit 1
  fi
  echo "[#] Checking for update..."
  current_local_hashsum=$($sha512sum_tool "$cli_path" | cut -d " " -f1)
  remote_=$(wget --timeout 6 -o /dev/null -q -O - 'https://raw.githubusercontent.com/ProtonVPN/protonvpn-cli/master/protonvpn-cli.sh')
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
  cli="$(cd "$(dirname "$0")" && pwd -P)/$(basename "$0")"
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

  if [[ ($errors_counter == 0) || ( -n $(which protonvpn-cli) ) ]]; then
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
    if [[ $(is_openvpn_currently_running) == true ]]; then  # Checking if OpenVPN is still active.
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
    config_id=$(< "$(get_protonvpn_cli_home)/.connection_config_id")
    vpn_server_details=$(get_vpn_server_details "$config_id")
    server_name=$(echo "$vpn_server_details" | cut -d '@' -f1)
    server_exit_country=$(echo "$vpn_server_details" | cut -d '@' -f2)
    server_tier=$(echo "$vpn_server_details" | cut -d '@' -f3)
    server_features=$(echo "$vpn_server_details" | cut -d '@' -f4)
    server_load=$(echo "$vpn_server_details" | cut -d '@' -f5)
    selected_protocol=$(tr '[:lower:]' '[:upper:]' < "$(get_protonvpn_cli_home)/.connection_selected_protocol")

    echo "[ProtonVPN] [Server Name]: $server_name"
    echo "[ProtonVPN] [OpenVPN Protocol]: $selected_protocol"
    echo "[ProtonVPN] [Exit Country]: $server_exit_country"
    echo "[ProtonVPN] [Tier]: $server_tier"
    echo "[ProtonVPN] [Server Features]: $server_features"
    echo "[ProtonVPN] [Server Load]: $server_load"

  fi
    exit 0

}

function get_openvpn_config_info() {
  vpn_ip=$(awk '$1 == "remote" {print $2}' "$(get_protonvpn_cli_home)/protonvpn_openvpn_config.conf" | head -n 1)
  vpn_port=$(awk '$1 == "remote" {print $3}' "$(get_protonvpn_cli_home)/protonvpn_openvpn_config.conf" | head -n 1)
  vpn_type=$(awk '$1 == "proto" {print $2}' "$(get_protonvpn_cli_home)/protonvpn_openvpn_config.conf" | head -n 1)
  vpn_device_name=$(grep -P "TUN/TAP device (.)+ opened" "$(get_protonvpn_cli_home)/connection_logs" | awk '{print $9}')
  echo "$vpn_ip@$vpn_port@$vpn_type@$vpn_device_name"
}

function killswitch() {
  if [[ ! -f "$(get_protonvpn_cli_home)/.enable_killswitch" ]]; then
    return
  fi

  if [[ $1 == "backup_rules" ]]; then
    if [[ $(detect_platform_type) == "linux" ]]; then
      iptables-save > "$(get_protonvpn_cli_home)/.iptables.save"
    elif [[ $(detect_platform_type) == "macos" ]]; then
      # Todo: logic
      false
    fi
  fi

  if [[ $1 == "enable" ]]; then
    if [[ $(detect_platform_type) == "linux" ]]; then
      vpn_port=$(get_openvpn_config_info | cut -d "@" -f2)
      vpn_type=$(get_openvpn_config_info | cut -d "@" -f3)
      vpn_device_name=$(get_openvpn_config_info | cut -d "@" -f4)
      iptables -F
      iptables -P INPUT DROP
      iptables -P OUTPUT DROP
      iptables -P FORWARD DROP

      iptables -A OUTPUT -o "$vpn_device_name" -j ACCEPT
      iptables -A INPUT -i "$vpn_device_name" -j ACCEPT
      iptables -A INPUT -i "$vpn_device_name" -m state --state ESTABLISHED,RELATED -j ACCEPT
      iptables -A OUTPUT -o "$vpn_device_name" -m state --state ESTABLISHED,RELATED -j ACCEPT
      iptables -A OUTPUT -p "$vpn_type" -m "$vpn_type" --dport "$vpn_port" -j ACCEPT
      iptables -A INPUT -p "$vpn_type" -m "$vpn_type" --sport "$vpn_port" -j ACCEPT

    elif [[ $(detect_platform_type) == "macos" ]]; then
     # Todo: logic
     false
    fi
  fi

  if [[ $1 == "disable" ]]; then
    if [[ $(detect_platform_type) == "linux" ]]; then
      iptables -F
      iptables-restore < "$(get_protonvpn_cli_home)/.iptables.save"
    elif [[ $(detect_platform_type) == "macos" ]]; then
      # Todo: logic
      false
    fi
  fi
}

function connect_to_fastest_vpn() {
  check_if_profile_initialized
  check_if_openvpn_is_currently_running
  check_if_internet_is_working_normally

  echo "Fetching ProtonVPN servers..."
  config_id=$(get_fastest_vpn_connection_id)
  selected_protocol="udp"
  openvpn_connect "$config_id" "$selected_protocol"
}

function connect_to_fastest_p2p_vpn() {
  check_if_profile_initialized
  check_if_openvpn_is_currently_running
  check_if_internet_is_working_normally

  echo "Fetching ProtonVPN servers..."
  config_id=$(get_fastest_vpn_connection_id "P2P")
  selected_protocol="udp"
  openvpn_connect "$config_id" "$selected_protocol"
}

function connect_to_fastest_tor_vpn() {
  check_if_profile_initialized
  check_if_openvpn_is_currently_running
  check_if_internet_is_working_normally

  echo "Fetching ProtonVPN servers..."
  config_id=$(get_fastest_vpn_connection_id "TOR")
  selected_protocol="udp"
  openvpn_connect "$config_id" "$selected_protocol"
}

function connect_to_fastest_secure_core_vpn() {
  check_if_profile_initialized
  check_if_openvpn_is_currently_running
  check_if_internet_is_working_normally

  echo "Fetching ProtonVPN servers..."
  config_id=$(get_fastest_vpn_connection_id "SECURE_CORE")
  selected_protocol="udp"
  openvpn_connect "$config_id" "$selected_protocol"
}

function connect_to_random_vpn() {
  check_if_profile_initialized
  check_if_openvpn_is_currently_running
  check_if_internet_is_working_normally

  echo "Fetching ProtonVPN servers..."
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

  config_id=$(< "$(get_protonvpn_cli_home)/.previous_connection_config_id")
  selected_protocol=$(< "$(get_protonvpn_cli_home)/.previous_connection_selected_protocol")
  openvpn_connect "$config_id" "$selected_protocol"
}

function reconnect_to_current_vpn() {
  check_if_profile_initialized

  if [[ ! -f "$(get_protonvpn_cli_home)/.connection_config_id" ]] ; then
    echo "[!] Error: ProtonVPN is not currently running."
    exit 1
  fi

  openvpn_disconnect "quiet" "dont_exit"
  if [[ $(is_openvpn_currently_running) == true ]]; then  # Checking if OpenVPN is still active.
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

  echo "Fetching ProtonVPN servers..."

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

  echo "Fetching ProtonVPN servers..."

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
    ARRAY+=("$counter")
    ARRAY+=("$data")
  done

  # Set DIALOGRC to a custom file including VI key binding.
  if [[ -f "$(get_protonvpn_cli_home)/.dialogrc" ]]; then
      DIALOGRC="$(get_protonvpn_cli_home)/.dialogrc"
      export DIALOGRC
  fi

  config_id=$(dialog --clear  --ascii-lines --output-fd 1 --title "ProtonVPN-CLI" --column-separator "@" \
    --menu "ID - Name - Country - Load - EntryIP - ExitIP - Features" 35 300 "$((${#ARRAY[@]}/2))" "${ARRAY[@]}" )
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

function connection_to_vpn_via_general_dialog_menu() {
  echo "[$] Loading..."
  check_if_profile_initialized
  check_if_openvpn_is_currently_running
  check_if_internet_is_working_normally

  wget --header 'x-pm-appversion: Other' \
       --header 'x-pm-apiversion: 3' \
       --header 'Accept: application/vnd.protonmail.v1+json' \
       --timeout 20 --tries 3 -q -O "$(get_protonvpn_cli_home)/.response_cache" \
       'https://api.protonmail.ch/vpn/logicals'

  if [[ $? != 0 ]]; then
    return
  fi
  # Set DIALOGRC to a custom file including VI key binding
  if [[ -f "$(get_protonvpn_cli_home)/.dialogrc" ]]; then
    DIALOGRC="$(get_protonvpn_cli_home)/.dialogrc"
    export DIALOGRC
  fi

  IFS=$'\n'
  dialog_menu 'init'
}

function dialog_menu() {
  case $1 in
  'init')
    initial_menu_items=('1' 'Quick Connect' '2' 'Country Selection' '3' 'Specialty Servers')

    menu_selection=$(dialog --clear --ascii-lines --output-fd 1 --title "ProtonVPN-CLI" --column-separator "@" \
      --menu "    ____             __            _    ______  _   __\n   / __ \_________  / /_____  ____| |  / / __ \/ | / /\n  / /_/ / ___/ __ \/ __/ __ \/ __ \ | / / /_/ /  |/ / \n / ____/ /  / /_/ / /_/ /_/ / / / / |/ / ____/ /|  /  \n/_/   /_/   \____/\__/\____/_/ /_/|___/_/   /_/ |_/   \n                                                      \n" 35 58 $((${#initial_menu_items[@]}/2)) "${initial_menu_items[@]}")
    clear

    if [[ -z "$menu_selection" ]]; then
      exit 1
    elif [[ "$menu_selection" == "1" ]]; then
      connect_to_fastest_vpn
    elif [[ "$menu_selection" == "2" ]]; then
      first_choice='countries'
      dialog_menu 'countries'
    elif [[ "$menu_selection" == "3" ]]; then
      first_choice='specialties'
      dialog_menu 'specialties'
    fi
    ;;
  'countries')
    countries=$(get_vpn_countries)

    ARRAY=()
    counter=0
    for i in $countries; do
      ((counter++))
      ARRAY+=("$counter")
      ARRAY+=("$i")
    done

    country_id=$(dialog --clear --ascii-lines --output-fd 1 --title "ProtonVPN-CLI" --column-separator "@" \
      --menu "Country" 35 50 $((${#ARRAY[@]}/2)) "${ARRAY[@]}" )
    clear

    if [[ -z "$country_id" ]]; then
      dialog_menu 'init'
    else
      server_list=$(get_countries_server_list "$country_id")
      dialog_menu 'servers'
    fi
    ;;
  'specialties')
    specialty_servers_menu_items=('1' 'Secure Core' '2' 'P2P' '3' 'TOR')

    menu_selection=$(dialog --clear --ascii-lines --output-fd 1 --title "ProtonVPN-CLI" --column-separator "@" \
      --menu "    ____             __            _    ______  _   __\n   / __ \_________  / /_____  ____| |  / / __ \/ | / /\n  / /_/ / ___/ __ \/ __/ __ \/ __ \ | / / /_/ /  |/ / \n / ____/ /  / /_/ / /_/ /_/ / / / / |/ / ____/ /|  /  \n/_/   /_/   \____/\__/\____/_/ /_/|___/_/   /_/ |_/   \n                                                      \n" 35 58 $((${#specialty_servers_menu_items[@]}/2)) "${specialty_servers_menu_items[@]}")
    clear

    if [[ -z "$menu_selection" ]]; then
      dialog_menu 'init'
    else
      server_list=$(get_specialty_servers "$menu_selection")
      dialog_menu 'servers'
    fi
    ;;
  'servers')
    if [[ -z "$server_list" ]]; then
      echo "[!] Error: Empty server list. This feature may not be accessible with your plan."
      exit 1
    fi

    ARRAY=()
    counter=0
    for i in $server_list; do
      data=$(echo "$i" | tr '@' ' ' | awk '{$1=""; print $0}' | tr ' ' '@')
      ((counter++))
      ARRAY+=("$counter")
      ARRAY+=("$data")
    done

    config_id=$(dialog --clear --ascii-lines --output-fd 1 --title "ProtonVPN-CLI" --column-separator "@" \
      --menu "ID - Name - Country - Load - EntryIP - ExitIP - Features" 35 80 $((${#ARRAY[@]}/2)) "${ARRAY[@]}")
    clear

    if [[ -z "$config_id" ]]; then
      dialog_menu "$first_choice"
    else
      dialog_menu 'protocols'
    fi
    ;;
  'protocols')
    available_protocols=("udp" " " "tcp" " ")
    selected_protocol=$(dialog --clear --ascii-lines --output-fd 1 --title "ProtonVPN-CLI" \
      --menu "Select Network Protocol" 35 80 2 "${available_protocols[@]}")
    clear

    if [[ -z "$selected_protocol" ]]; then
      dialog_menu 'servers'
    else
      counter=1
      for i in $server_list; do
        if ((counter == config_id)); then
          config_id=$(echo "$i" | cut -d " " -f1)
          break
        fi
        ((counter++))
      done
      openvpn_connect "$config_id" "$selected_protocol"
    fi
    ;;
  *)
    echo "[!] Error: Invalid menu entry."
    exit 1
    ;;
  esac
}

function get_specialty_servers(){
  response_cache_path="$(get_protonvpn_cli_home)/.response_cache"
  tier=$(cat "$(get_protonvpn_cli_home)/protonvpn_tier")

  output=`$python <<END
import json
response_cache = open("""$response_cache_path""", "r").read()
json_parsed_response = json.loads(response_cache)
output = []
for _ in json_parsed_response["LogicalServers"]:
    if (_["Tier"] <= int("""$tier""")):
        output.append(_)

all_features = {"Secure Core": 1, "TOR": 2, "P2P": 4, "XOR": 8, "IPV6": 16}

if int('$1') == 1:
	selected_feature = 1
if int('$1') == 2:
	selected_feature = 4
if int('$1') == 3:
	selected_feature = 2

for _ in output:
    server_features_index = int(_["Features"])
    server_features  = []
    server_features_output = ""
    if server_features_index == selected_feature:
	    for f in all_features.keys():
	        if (server_features_index & all_features[f]) > 0:
	            server_features.append(f)
	    if _["Tier"] == 2:
	        server_features.append("Plus")
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

function get_vpn_countries() {
  response_cache_path="$(get_protonvpn_cli_home)/.response_cache"

  tier=$(cat "$(get_protonvpn_cli_home)/protonvpn_tier")
  output=`$python <<END
import json, random
response_cache = open("""$response_cache_path""", "r").read()
json_parsed_response = json.loads(response_cache)
output = []
for _ in json_parsed_response["LogicalServers"]:
    if (_["Tier"] <= int("""$tier""")):
        output.append(_)

all_features = {"SECURE_CORE": 1, "TOR": 2, "P2P": 4, "XOR": 8, "IPV6": 16}

countryIsoCodes = {'AW': 'Aruba', 'AF': 'Afghanistan', 'AO': 'Angola', 'AI': 'Anguilla', 'AL': 'Albania', 'AD': 'Andorra', 'AE': 'United Arab Emirates', 'AR': 'Argentina', 'AM': 'Armenia', 'AS': 'American Samoa',
'AQ': 'Antarctica', 'TF': 'French Southern Territories', 'AG': 'Antigua and Barbuda', 'AU': 'Australia', 'AT': 'Austria', 'AZ': 'Azerbaijan', 'BI': 'Burundi', 'BE': 'Belgium', 'BJ': 'Benin', 'BQ': 'Bonaire, Sint Eustatius and Saba', 'BF': 'Burkina Faso', 'BD': 'Bangladesh', 'BG': 'Bulgaria', 'BH': 'Bahrain', 'BS': 'Bahamas', 'BA': 'Bosnia and Herzegovina', 'BY': 'Belarus', 'BZ': 'Belize', 'BM': 'Bermuda', 'BO': 'Bolivia, Plurinational State of', 'BR': 'Brazil', 'BB': 'Barbados', 'BN': 'Brunei Darussalam', 'BT': 'Bhutan', 'BV': 'Bouvet Island', 'BW': 'Botswana', 'CF': 'Central African Republic', 'CA': 'Canada', 'CH': 'Switzerland', 'CL': 'Chile', 'CN': 'China', 'CM': 'Cameroon', 'CD': 'Congo', 'CG': 'Congo', 'CK': 'Cook Islands', 'CO': 'Colombia', 'KM': 'Comoros', 'CV': 'Cabo Verde', 'CR': 'Costa Rica', 'CU': 'Cuba', 'CX': 'Christmas Island', 'KY': 'Cayman Islands', 'CY': 'Cyprus', 'CZ': 'Czechia', 'DE': 'Germany', 'DJ': 'Djibouti', 'DM': 'Dominica', 'DK': 'Denmark', 'DO': 'Dominican Republic', 'DZ': 'Algeria', 'EC': 'Ecuador', 'EG': 'Egypt', 'ER': 'Eritrea', 'EH': 'Western Sahara', 'ES': 'Spain', 'EE': 'Estonia', 'ET': 'Ethiopia', 'FI': 'Finland', 'FJ': 'Fiji', 'FK': 'Falkland Islands (Malvinas)', 'FR': 'France', 'FO': 'Faroe Islands', 'FM': 'Micronesia, Federated States of', 'GA': 'Gabon', 'GB': 'United Kingdom', 'GE': 'Georgia', 'GG': 'Guernsey', 'GH': 'Ghana', 'GI': 'Gibraltar', 'GN': 'Guinea', 'GP': 'Guadeloupe', 'GM': 'Gambia', 'GW': 'Guinea-Bissau', 'GQ': 'Equatorial Guinea', 'GR': 'Greece', 'GD': 'Grenada', 'GL': 'Greenland', 'GT': 'Guatemala', 'GF': 'French Guiana', 'GU': 'Guam', 'GY': 'Guyana', 'HK': 'Hong Kong', 'HM': 'Heard Island and McDonald Islands', 'HN': 'Honduras', 'HR': 'Croatia', 'HT': 'Haiti', 'HU': 'Hungary', 'ID': 'Indonesia', 'IM': 'Isle of Man', 'IN': 'India', 'IO': 'British Indian Ocean Territory', 'IE': 'Ireland', 'IR': 'Iran', 'IQ': 'Iraq', 'IS': 'Iceland', 'IL': 'Israel', 'IT': 'Italy', 'JM': 'Jamaica', 'JE': 'Jersey', 'JO': 'Jordan', 'JP': 'Japan', 'KZ': 'Kazakhstan', 'KE': 'Kenya', 'KG': 'Kyrgyzstan', 'KH': 'Cambodia', 'KI': 'Kiribati', 'KN': 'Saint Kitts and Nevis', 'KR': 'South Korea', 'KW': 'Kuwait', 'LA': "Lao People's Democratic Republic", 'LB': 'Lebanon', 'LR': 'Liberia', 'LY': 'Libya', 'LC': 'Saint Lucia', 'LI': 'Liechtenstein', 'LK': 'Sri Lanka', 'LS': 'Lesotho', 'LT': 'Lithuania', 'LU': 'Luxembourg', 'LV': 'Latvia', 'MO': 'Macao', 'MF': 'Saint Martin (French part)', 'MA': 'Morocco', 'MC': 'Monaco', 'MD': 'Moldova', 'MG': 'Madagascar', 'MV': 'Maldives', 'MX': 'Mexico', 'MH': 'Marshall Islands', 'MK': 'Macedonia', 'ML': 'Mali', 'MT': 'Malta', 'MM': 'Myanmar', 'ME':
'Montenegro', 'MN': 'Mongolia', 'MP': 'Northern Mariana Islands', 'MZ': 'Mozambique', 'MR': 'Mauritania', 'MS': 'Montserrat', 'MQ': 'Martinique', 'MU': 'Mauritius', 'MW': 'Malawi', 'MY': 'Malaysia', 'YT': 'Mayotte', 'NA': 'Namibia', 'NC': 'New Caledonia', 'NE': 'Niger', 'NF': 'Norfolk Island', 'NG': 'Nigeria', 'NI': 'Nicaragua', 'NU': 'Niue', 'NL': 'Netherlands', 'NO': 'Norway', 'NP': 'Nepal', 'NR': 'Nauru', 'NZ': 'New Zealand', 'OM': 'Oman', 'PK': 'Pakistan', 'PA': 'Panama', 'PN': 'Pitcairn', 'PE': 'Peru', 'PH': 'Philippines', 'PW': 'Palau', 'PG': 'Papua New Guinea', 'PL': 'Poland', 'PR': 'Puerto Rico', 'KP': "South Korea", 'PT': 'Portugal', 'PY': 'Paraguay', 'PS': 'Palestine, State of', 'PF': 'French Polynesia', 'QA': 'Qatar', 'RE': 'Reunion', 'RO': 'Romania', 'RU': 'Russian Federation', 'RW': 'Rwanda', 'SA': 'Saudi Arabia', 'SD':
'Sudan', 'SN': 'Senegal', 'SG': 'Singapore', 'GS': 'South Georgia and the South Sandwich Islands', 'SH': 'Saint Helena, Ascension and Tristan da Cunha', 'SJ': 'Svalbard and Jan Mayen', 'SB': 'Solomon Islands', 'SL': 'Sierra Leone', 'SV': 'El Salvador', 'SM': 'San Marino', 'SO': 'Somalia', 'PM': 'Saint Pierre and Miquelon', 'RS': 'Serbia', 'SS': 'South Sudan', 'ST': 'Sao Tome and Principe', 'SR': 'Suriname', 'SK': 'Slovakia', 'SI': 'Slovenia', 'SE': 'Sweden', 'SZ': 'Swaziland', 'SX': 'Sint Maarten (Dutch part)', 'SC': 'Seychelles', 'SY': 'Syrian Arab Republic', 'TC': 'Turks and Caicos Islands', 'TD': 'Chad', 'TG': 'Togo', 'TH': 'Thailand', 'TJ': 'Tajikistan', 'TK': 'Tokelau', 'TM': 'Turkmenistan', 'TL': 'Timor-Leste', 'TO': 'Tonga', 'TT': 'Trinidad and Tobago', 'TN': 'Tunisia', 'TR': 'Turkey', 'TV': 'Tuvalu', 'TW': 'Taiwan, Province of China', 'TZ': 'Tanzania',
'UG': 'Uganda',"UK" : 'United Kingdom' ,'UA': 'Ukraine', 'UM': 'United States Minor Outlying Islands', 'UY': 'Uruguay', 'US': 'United States', 'UZ': 'Uzbekistan', 'VA': 'Holy See (Vatican City State)', 'VC': 'Saint Vincent and the Grenadines', 'VE': 'Venezuela', 'VG': 'Virgin Islands, British', 'VI': 'Virgin Islands, U.S.', 'VN': 'Viet Nam', 'VU': 'Vanuatu', 'WF': 'Wallis and Futuna', 'WS': 'Samoa', 'YE': 'Yemen', 'ZA': 'South Africa', 'ZM': 'Zambia', 'ZW': 'Zimbabwe'}

countries = []
for _ in output:
    if countryIsoCodes[_['EntryCountry']] not in countries:
        countries.append(countryIsoCodes[_['EntryCountry']])
        o = "{}".format(countryIsoCodes[_['EntryCountry']])
        print(o)
END`

  echo "$output"
}

function get_countries_server_list() {
  response_cache_path="$(get_protonvpn_cli_home)/.response_cache"
  tier=$(cat "$(get_protonvpn_cli_home)/protonvpn_tier")

  output=`$python <<END
import json
response_cache = open("""$response_cache_path""", "r").read()
json_parsed_response = json.loads(response_cache)
output = []
for _ in json_parsed_response["LogicalServers"]:
    if (_["Tier"] <= int("""$tier""")):
        output.append(_)

all_features = {"SECURE_CORE": 1, "TOR": 2, "P2P": 4, "XOR": 8, "IPV6": 16}

countries = []
for _ in output:
  if _['EntryCountry'] not in countries:
    countries.append(_['EntryCountry'])

for i, country in enumerate(countries):
	if str(i+1) == """$1""":
		selected_country = country

best_server = ""
for _ in output:
  if _['EntryCountry'] == selected_country:
    if best_server == "":
      best_server = _
    if best_server['Score'] > _['Score']:
      best_server = _
o = "{} {}@{}@{}@{}@{}@{}".format(best_server["ID"], "Connect To Fastest", \
  " ", " ", " ", " ", " ")
print(o)

for _ in output:
    server_features_index = int(_["Features"])
    server_features  = []
    server_features_output = ""
    if _['EntryCountry'] == selected_country:
	    for f in all_features.keys():
	        if (server_features_index & all_features[f]) > 0:
	            server_features.append(f)
	    if _["Tier"] == 2:
	        server_features.append("Plus")
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

function get_vpn_server_details() {
  response_cache_path="$(get_protonvpn_cli_home)/.response_cache.tmp"
  wget --header 'x-pm-appversion: Other' \
       --header 'x-pm-apiversion: 3' \
       --header 'Accept: application/vnd.protonmail.v1+json' \
       --timeout 7 --tries 1 -q -O "$response_cache_path" \
       'https://api.protonmail.ch/vpn/logicals'
  if [[ $? != 0 ]]; then
    response_cache_path="$(get_protonvpn_cli_home)/.response_cache"
  fi
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
        if _["Tier"] == 2:
            server_features.append("Plus")
        if len(server_features) == 0:
            server_features_value = "None"
        else:
            server_features_value = ",".join(server_features)
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
                         -o /dev/null \
                         --timeout 20 --tries 1 -q -O - "https://api.protonmail.ch/vpn/logicals" | tee "$(get_protonvpn_cli_home)/.response_cache")
  if [[ $? != 0 ]]; then
    return
  fi
  tier=$(< "$(get_protonvpn_cli_home)/protonvpn_tier")
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
  if _["Tier"] == 2:
      server_features.append("Plus")
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

available_countries = candidates_2.keys()
available_countries = sorted(available_countries)
for _ in available_countries:
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
                         -o /dev/null \
                         --timeout 20 --tries 1 -q -O - "https://api.protonmail.ch/vpn/logicals" | tee "$(get_protonvpn_cli_home)/.response_cache")
  if [[ $? != 0 ]]; then
    return
  fi

  tier=$(< "$(get_protonvpn_cli_home)/protonvpn_tier")
  output=`$python <<END
import json, math, random
json_parsed_response = json.loads("""$response_output""")

all_features = {"SECURE_CORE": 1, "TOR": 2, "P2P": 4, "XOR": 8, "IPV6": 16}
excluded_features_on_fastest_connect = ["TOR"]
required_features = ["$required_feature"] if "$required_feature" in all_features else []
if "TOR" in required_features:
    excluded_features_on_fastest_connect.remove("TOR")

candidates_1 = []
for _ in json_parsed_response["LogicalServers"]:
    server_features_index = int(_["Features"])
    server_features  = []
    for f in all_features.keys():
        if (server_features_index & all_features[f]) > 0:
            server_features.append(f)
    if _["Tier"] == 2:
        server_features.append("Plus")
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
                         -o /dev/null \
                         --timeout 20 --tries 1 -q -O - "https://api.protonmail.ch/vpn/logicals" | tee "$(get_protonvpn_cli_home)/.response_cache")

  if [[ $? != 0 ]]; then
    return
  fi

  tier=$(< "$(get_protonvpn_cli_home)/protonvpn_tier")
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

function get_vpn_config_details() {
  response_output=$(wget --header 'x-pm-appversion: Other' \
                         --header 'x-pm-apiversion: 3' \
                         --header 'Accept: application/vnd.protonmail.v1+json' \
                         -o /dev/null \
                         --timeout 20 --tries 1 -q -O - "https://api.protonmail.ch/vpn/logicals" | tee "$(get_protonvpn_cli_home)/.response_cache")

  if [[ $? != 0 ]]; then
    return
  fi

  tier=$(< "$(get_protonvpn_cli_home)/protonvpn_tier")
  output=`$python <<END
import json, random
json_parsed_response = json.loads("""$response_output""")
output = []
for _ in json_parsed_response["LogicalServers"]:
    if (_["Tier"] <= int("""$tier""")):
        output.append(_)
all_features = {"SECURE_CORE": 1, "TOR": 2, "P2P": 4, "XOR": 8, "IPV6": 16}
output = sorted(output, key=lambda k: k['Name'])
for _ in output:
    server_features_index = int(_["Features"])
    server_features  = []
    server_features_output = ""
    for f in all_features.keys():
        if (server_features_index & all_features[f]) > 0:
            server_features.append(f)
    if _["Tier"] == 2:
        server_features.append("Plus")
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

function show_version() {
    echo
    echo -e "ProtonVPN Command-Line Tool – v$version"
    echo "Copyright (c) 2013-2018 Proton Technologies A.G. (Switzerland)"
    echo "Distributed under the MIT software license (see the accompanying file license.md)."
    echo
}

function help_message() {
    echo
    echo -e "ProtonVPN Command-Line Tool – v$version\n"
    echo -e "Usage: $(basename $0) [option]\n"
    echo "Options:"
    echo "   --init                              Initialize ProtonVPN profile on the machine."
    echo "   -c, --connect                       Select and connect to a ProtonVPN server."
    echo "   -c [server-name] [protocol]         Connect to a ProtonVPN server by name."
    echo "   -m, --menu                          Select and connect to a ProtonVPN server from a menu."
    echo "   -r, --random-connect                Connect to a random ProtonVPN server."
    echo "   -l, --last-connect                  Connect to the previously used ProtonVPN server."
    echo "   -f, --fastest-connect               Connect to the fastest available ProtonVPN server."
    echo "   -p2p, --p2p-connect                 Connect to the fastest available P2P ProtonVPN server."
    echo "   -tor, --tor-connect                 Connect to the fastest available ProtonVPN TOR server."
    echo "   -sc, --secure-core-connect          Connect to the fastest available ProtonVPN SecureCore server."
    echo "   -cc, --country-connect              Select and connect to a ProtonVPN server by country."
    echo "   -cc [country-name] [protocol]       Connect to the fastest available server in a specific country."
    echo "   -d, --disconnect                    Disconnect the current session."
    echo "   --reconnect                         Reconnect to the current ProtonVPN server."
    echo "   --ip                                Print the current public IP address."
    echo "   --status                            Print connection status."
    echo "   --update                            Update protonvpn-cli."
    echo "   --install                           Install protonvpn-cli."
    echo "   --uninstall                         Uninstall protonvpn-cli."
    echo "   -v, --version                       Display version."
    echo "   -h, --help                          Show this help message."
    echo

    exit 0
}

check_requirements
user_input="$1"
case $user_input in
  ""|"-h"|"--help"|"--h"|"-help"|"help") help_message
    ;;
  "-v"|"--v"|"-version"|"--version") show_version
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
  "-tor"|"--tor"|"-tor-connect"|"--tor-connect") connect_to_fastest_tor_vpn
    ;;
  "-sc"|"--sc"|"-secure-core-connect"|"--secure-core-connect") connect_to_fastest_secure_core_vpn
    ;;
  "-cc"|"--cc"|"-country-connect"|"--country-connect")
    if [[ $# == 1 ]]; then
      connection_to_vpn_via_dialog_menu "countries"
    elif [[ $# -gt 1 ]]; then
      connect_to_specific_server "$2" "$3" "country"
    fi
    ;;
  "-c"|"-connect"|"--c"|"--connect")
    if [[ $# == 1 ]]; then
      connection_to_vpn_via_dialog_menu "servers"
    elif [[ $# -gt 1 ]]; then
      connect_to_specific_server "$2" "$3" "server"
    fi
    ;;
  "-m"|"--m"|"-menu"|"--menu") connection_to_vpn_via_general_dialog_menu
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
