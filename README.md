# f5scan
F5 BIG IP Scanner for CVE-2020-5902 by bt0

More information about the Vulnerability:
https://support.f5.com/csp/article/K52145254?sf235665517=1

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)

## Requirements:

- python3+
- shodan
- colorama
- urlopen
- pyOpenSSL

  * $ pip3 install -r requirements

## Options

  -h, --help            show this help message and exit
  -H HOST, --host HOST  IP or Hostname of target
  -p PORT, --port PORT  Port of target. Default=443
  -hl HOSTLIST, --hostlist HOSTLIST
                        Use a hosts list e.g. ./hosts.txt
  -s, --shodan          Search for hosts in Shodan (Needs api key)
  -e, --exploit         exploit target
  -c COMMAND, --command COMMAND
                        command to execute
  -lf LFI, --lfi LFI    File to read using LFI Vulnerability
  --version             show program's version number and exit