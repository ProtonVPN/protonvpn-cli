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

#### (via `git`) ####

```bash
$ sudo bash -c "git clone https://github.com/ProtonVPN/protonvpn-cli.git && ./protonvpn-cli/protonvpn-cli.sh --install"
```
#### (via `wget`) ####
```bash
$ wget "https://github.com/ProtonVPN/protonvpn-cli/raw/master/protonvpn-cli.sh" -O "protonvpn-cli.sh" && sudo bash protonvpn-cli.sh --install
```


# Usage #

| **Command**                                   | **Description**                                                |
| :-------------------------------------------- | :------------------------------------------------------------- |
| `protonvpn-cli --init`                        | Initialize ProtonVPN profile on the machine.                   |
| `protonvpn-cli -c, --connect`                 | Select and connect to a ProtonVPN server.                      |
| `protonvpn-cli -c [server-name] [protocol]`   | Connect to a ProtonVPN server by name.                         |
| `protonvpn-cli -r, --random-connect`          | Connect to a random ProtonVPN server.                          |
| `protonvpn-cli -l, --last-connect`            | Connect to the previously used ProtonVPN server.               |
| `protonvpn-cli -f, --fastest-connect`         | Connect to the fastest available ProtonVPN server.             |
| `protonvpn-cli -p2p, --p2p-connect`           | Connect to the fastest available P2P ProtonVPN server.         |
| `protonvpn-cli -cc, --country-connect`        | Select and connect to a ProtonVPN server by country.           |
| `protonvpn-cli -cc [country-name] [protocol]` | Connect to the fastest available server in a specific country. |
| `protonvpn-cli -d, --disconnect`              | Disconnect the current session.                                |
| `protonvpn-cli --reconnect`                   | Reconnect to the current server.                               |
| `protonvpn-cli --ip`                          | Print the current public IP address.                           |
| `protonvpn-cli --status`                      | Print connection status.                                       |
| `protonvpn-cli --update`                      | Update protonvpn-cli.                                          |
| `protonvpn-cli --install`                     | Install protonvpn-cli.                                         |
| `protonvpn-cli --uninstall`                   | Uninstall protonvpn-cli.                                       |
| `protonvpn-cli --version`                     | Display version.                                               |
| `protonvpn-cli --help`                        | Show help message.                                             |


protonvpn-cli can also be used by typing `pvpn`, once installed.


# Compatibility #
* Linux
* macOS

# License #

protonvpn-cli is released under the MIT license.
