import re
import pynetbox
import yaml
import logging
import time
import sys
import requests
from pprint import pprint
from pyzabbix import ZabbixAPI

logger = logging.getLogger('STDOUT')
logging.Formatter("%(asctime)s;%(levelname)s;%(message)s",'%Y-%m-%d %H:%M:%S')

with open("config.yml", 'r', encoding="utf-8") as ymlfile:
    config = yaml.load(ymlfile, Loader=yaml.FullLoader)

zapi = ZabbixAPI(server=config['zabbix.url'])
zapi.login(config['zabbix.user'], config['zabbix.password'])

from requests.packages.urllib3.exceptions import InsecureRequestWarning
session = requests.Session()
session.verify = False
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
netbox = pynetbox.api(url=config['netbox.url'], token=config['netbox.token'])
netbox.http_session = session
netbox.http_session.verify = False

########################################################################################################################

def get_group_ids(site, role):

    temp = []

    group_name = config['group'][site][role]

    for name in group_name:
        group_id = zapi.hostgroup.get(filter={"name": name})
        temp.append({'groupid': group_id[0]['groupid']})

    return temp

def get_template_ids(role):

    temp = []

    for template_name in config['template'][role]:
        template_id = zapi.template.get(filter={"host": template_name})
        temp.append({'templateid': template_id[0]['templateid']})

    return temp

########################################################################

for role in config['processed_roles']:

    netbox_result = {}
    netbox_array = []
    zabbix_result = {}
    zabbix_array = []

    # Get NetBox Device list
    devices_of_netbox = netbox.dcim.devices.filter(role=role, status='active')
    for device in devices_of_netbox:
        device = dict(device)

        try:
            if device['primary_ip'] != None and device['primary_ip']['address'].split('/')[0] != None and device['site'] != None and device['status']['value'] != None and device['device_role']['name'] != None\
                    and device['device_type']['manufacturer'] != None and device['device_type']['model'] != None and device['platform'] != None:

                if device['status']['value'] == 'active':
                    device['status']['value'] = 0
                else:
                    device['status']['value'] = 1

                netbox_array.append(device['name'])
                netbox_result[device['name']] = {
                                                        'ip': device['primary_ip']['address'].split('/')[0],
                                                        'site': device['site']['name'],
                                                        'status': device['status']['value'],
                                                        'role': device['device_role']['name'],
                                                        'model': device['device_type']['manufacturer']['name'] + ' ' + device['device_type']['model'],
                                                        'platform': device['platform']['slug'],
                                                        'needed_templates': get_template_ids(device['device_role']['name']),
                                                        'group': get_group_ids(device['site']['name'], device['device_role']['name'])
                                                      }

        except:
            logger.error('=== Device ' + device['name'] + ' Failed ===')
            print('=== Device ' + device['name'] + ' Failed ===')
            pass

    # Create/Update Zabbix

    for device in netbox_result.items():
        host = zapi.host.get(filter={'host': device[0]})
        if host:
            host_id = [key['hostid'] for key in host]
            if config['debug'] == 0:
                # Update host
                zapi.host.update({'hostid': host_id[0],
                                  'status': device[1]['status']})
                logger.info(device[0] + ' (' + device[1]['ip'] + ')' + ': Existing => Update')
                print(device[0] + ' (' + device[1]['ip'] + ')' + ': Existing => Update')
                # Update Host Interface

                interface_id = [key['interfaceid'] for key in zapi.hostinterface.get(filter={'hostid': host_id[0], 'type': 2})]
                zapi.hostinterface.update({
                                            'interfaceid': interface_id[0],
                                            'ip': device[1]['ip'],
                                            'dns': '',
                                            'port': 161,
                                            'useip': 1,
                                            'main': 1
                                         })

            else:
                logger.debug(device[0] + ' (' + device[1]['ip'] + ')' + ': Existing => Update [DRY RUN]')
                print(device[0] + ' (' + device[1]['ip'] + ')' + ': Existing => Update [DRY RUN]')
        else:
            if config['debug'] == 0:
                host_id = zapi.host.create({
                                            'host': device[0],
                                            'name': device[0],
                                            'interfaces': [{'type': 1, 'main': 1, 'ip': device[1]['ip'], 'dns': '', 'port': 10050, 'useip': 1},
                                                           {'type': '2', 'main': 1, 'ip': device[1]['ip'], 'dns': '', 'port': 161, 'useip': 1, 'details': {'version': 2, 'community': "{$SNMP_COMMUNITY}"}}
                                                           ],
                                            'templates': device[1]['needed_templates'],
                                            'groups': device[1]['group'],
                                            'status': device[1]['status']
                                           })
                logger.info(device[0] + ' (' + device[1]['ip'] + ')' + ': Not existing => Create')
                print(device[0] + ' (' + device[1]['ip'] + ')' + ': Not existing => Create')
            else:
                logger.debug(device[0] + ' (' + device[1]['ip'] + ')' + ': Not existing => Create [DRY RUN]')
                print(device[0] + ' (' + device[1]['ip'] + ')' + ': Not existing => Create [DRY RUN]')

logger.info('=== End ' + time.asctime() + ' ===')
print('=== End ' + time.asctime() + ' ===')
