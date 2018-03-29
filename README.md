*protonvpn-cli*
================

![protonvpn-cli](https://i.imgur.com/tDrwkX5l.png)

# Overview #
protonvpn-cli is a command-line tool for Linux and macOS.

# Requirements #

* `openvpn`
* `python`
* `dialog`
* `wget`
* `sysctl`
* `sha512sum`

The program automatically checks for missing requirements.


# Installation #

```bash
$ git clone "https://github.com/protonvpn/protonvpn-cli"
$ cd protonvpn-cli
$ sudo ./protonvpn-cli.sh --install
```

### Or (one-liner): ###

```bash
$ sudo bash -c "git clone https://github.com/ProtonVPN/protonvpn-cli.git ; ./protonvpn-cli/protonvpn-cli.sh --install"
```

# Usage #

| **Command**                                  | **Description**                               |
| :------------------------------------------- | :-------------------------------------------- |
| `protonvpn-cli --init`                       | Initialize ProtonVPN profile on the machine.  |
| `protonvpn-cli -c, --connect`                | Select a server from the menu.                |
| `protonvpn-cli -c [server-name] [protocol]`  | Connect directly to a ProtonVPN server.       |
| `protonvpn-cli -r, --random-connect`         | Connect to a random ProtonVPN server.         |
| `protonvpn-cli -f, --fastest-connect`        | Connect to a fast ProtonVPN server.           |
| `protonvpn-cli -d, --disconnect`             | Disconnect the current session.               |
| `protonvpn-cli --ip`                         | Print the current public IP address.          |
| `protonvpn-cli --update`                     | Update protonvpn-cli.                         |
| `protonvpn-cli --install`                    | Install protonvpn-cli.                        |
| `protonvpn-cli --uninstall`                  | Uninstall protonvpn-cli.                      |
| `protonvpn-cli --help`                       | Show help message.                            |


protonvpn-cli can also be used by typing `pvpn`, once installed.


# Compatibility #
* Linux
* macOS
