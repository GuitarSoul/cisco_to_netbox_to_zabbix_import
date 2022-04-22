# Cisco to Netbox integration
Script gathers all needed info from Cisco devices and creates entities in Netbox (devices, interfaces, prefixes, ip addresses, cdp connections etc)

This script has two parts:
- First script is based on https://github.com/pavelstef/cisco_devices_info_collector and parses all info from Cisco devices.
- Second script creates entities in Netbox (devices, interfaces, prefixes, ip addresses, cdp connections, vlans, hsrp, wireless ap etc)

What the main.py script does:

1. Connects to ips of Cisco devices written in ip_list_all.txt or ip_list.txt files by netmiko or paramiko
2. Gathers information according to templates
3. Parses data and writes into api/"device_name".csv files in json format

Script's main purpose is full integration between Cisco and Netbox (https://netbox.readthedocs.io/en/stable/)

Script works fine with IOS, NX-OS, XR, SG-220, Air-OS but can have some problems with "slow" devices when getting responce takes a long time.
Script might fail trying to connect to some devices ,especially when connecting to more than 20 devices simultaneously in a thread.
script worked fine and was tested in one Enterprise network environment only, and some templates were edited to work in that environment.

What the Cisco_To_Netbox.py script does:

Reades text files containing json data of network devices and creates/updates entities in Netbox.

Script uses custom fields, you must add these fields to write acl information

![image](https://user-images.githubusercontent.com/101651215/158596859-1df20062-a851-470a-849b-b1173ac6cb15.png)


1. Edit yaml file
2. Add ip list to connect
3. Run the script main.py
4. Run Cisco_To_Netbox.py


----------------------------------------------------------------------------------------------------------------------------------------------------------------
I also have changed some values in "site-packages\netmiko\base_connection.py", that helped me to solve problems with slow response from cli:

conn_timeout=20
banner_timeout=20
fast_cli=False
