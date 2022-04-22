# (Cisco + ESXI VM) -> Netbox -> Zabbix

Netbox 3.2 +
Zabbix 6 +

Cisco Devices:
  - Script uses "confluence url page" or "txt file in the same folder" to get ip list to connect
  - Script gathers all needed info by ssh
  - Parses data and writes into api/"device_name".csv files in json format (Some examples are in api folder)
  - Creates entities in Netbox (devices, interfaces, prefixes, ip addresses, vlans, cdp connections, inventory)
  - Zabbix script goes through all devices and creates/updates hosts on Zabbix server

ESXI VM:
  - Script gathers all needed info from ESXI server by "pyVim" module
  - Creates entities in Netbox 

Details:
  - Script's main purpose is full integration between Cisco and Netbox (https://netbox.readthedocs.io/en/stable/)
  - Script works fine with IOS, NX-OS, XR, SG-220, Air-OS but can have some problems with "slow" devices when getting responce takes a long time.
  - Use -- help when running script in cmd
  
To run the script once a day in a background just add this line to crontab file: 
  - 0 0 * * * (cd /path_to_script_folder && env/bin/python Cisco_To_Json.py -f confluence && env/bin/python Cisco_To_Netbox.py -l all && env/bin/python Netbox_To_Zabbix.py ) > /path_to_log_folder/Cron_Logs.txt
  - Script Cisco_To_Json.py -f confluence

Attention:
  - Script Cisco_To_Netbox uses custom fields, you must add these fields to write acl information

  ![image](https://user-images.githubusercontent.com/101651215/158596859-1df20062-a851-470a-849b-b1173ac6cb15.png)
  
  - Script might fail trying to connect to some devices ,especially when connecting to more than 20 devices simultaneously in a thread.
  - Script worked fine and was tested in one Enterprise network environment only, and some templates were edited to work in that environment!

Instructions:
  1. Edit yaml file
  2. Run a .py file in cmd or all of them via Cron
  


----------------------------------------------------------------------------------------------------------------------------------------------------------------
Create all needed folders first
![image](https://user-images.githubusercontent.com/101651215/164753440-fe977c92-1498-419a-8300-90f3f0dc2fdb.png)

