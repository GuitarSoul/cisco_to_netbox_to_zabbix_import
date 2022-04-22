# (Cisco + ESXI VM) to Netbox integration

Cisco Devices:
  - Script gathers all needed info by ssh
  - Parses data and writes into api/"device_name".csv files in json format
  - Creates entities in Netbox (devices, interfaces, prefixes, ip addresses, vlans, cdp connections, inventory)
ESXI VM:
  - Script gathers all needed info from ESXI server by "pyVim" module
  - Creates entities in Netbox 

Detailes:
  Script's main purpose is full integration between Cisco and Netbox (https://netbox.readthedocs.io/en/stable/)
  Script works fine with IOS, NX-OS, XR, SG-220, Air-OS but can have some problems with "slow" devices when getting responce takes a long time.
  
To run the script once a day in a background just add this line to crontab file: 
  0 0 * * * (cd /path_to_script_folder && env/bin/python Cisco_To_Json.py -f all && env/bin/python Cisco_To_Netbox.py -l confluence && env/bin/python Netbox_To_Zabbix.py ) > /path_to_log_folder/Cron_Logs.txt

Attention:
  Script Cisco_To_Netbox uses custom fields, you must add these fields to write acl information
  ![image](https://user-images.githubusercontent.com/101651215/158596859-1df20062-a851-470a-849b-b1173ac6cb15.png)
  
  Script might fail trying to connect to some devices ,especially when connecting to more than 20 devices simultaneously in a thread.
  Script worked fine and was tested in one Enterprise network environment only, and some templates were edited to work in that environment!

Instructions:
  1. Edit yaml file
  2. Add ip list to connect
  3. Run the script main.py
  4. Run Cisco_To_Netbox.py


----------------------------------------------------------------------------------------------------------------------------------------------------------------

