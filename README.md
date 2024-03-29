# (Cisco + ESXI VM) -> Netbox -> Zabbix

Tested on Netbox 3.2 +

Tested on Zabbix 6 +

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
  - Examples to run basic script "Script Cisco_To_Json.py -f confluence | all | test"

Attention:
  - Script Cisco_To_Netbox uses custom fields, you must add these fields to write acl information
  - IMPORTANT! Devices are associated with sites by their hostname. Hostname MUST include a site_name. For example 78-SITE_NAME-ASW01. 78 - is a city code.
  - For Cisco ASR edit  chars = ['RP/0/RSP0/CPU0:', '>', '#'] variable in Cisco_To_json.py according to your asr devices hostnames to cut theese chars off 
  - Highly recommended to include "router" and "switch_layer_3" to device_role list in Netbox, this is a cryteria by which script adds description to prefixes
  
  ![image](https://user-images.githubusercontent.com/101651215/158596859-1df20062-a851-470a-849b-b1173ac6cb15.png)
  
  - Script might fail trying to connect to some devices ,especially when connecting to more than 20 devices simultaneously in a thread.
  - Script worked fine and was tested in one Enterprise network environment only, and some templates were edited to work in that environment!

Instructions:

Create all needed folders first

![image](https://user-images.githubusercontent.com/101651215/164753440-fe977c92-1498-419a-8300-90f3f0dc2fdb.png)


  1. Edit yaml file
  2. Run a .py file in cmd or all of them via Cron, use --help to see all possible arguments
  


----------------------------------------------------------------------------------------------------------------------------------------------------------------
![image](https://user-images.githubusercontent.com/101651215/165098414-bdd17a5f-e774-4217-8d17-20ae9a8d5cca.png)


![Снимок](https://user-images.githubusercontent.com/101651215/165099884-ac971cd7-8e52-429e-8aaf-898315773818.JPG)
