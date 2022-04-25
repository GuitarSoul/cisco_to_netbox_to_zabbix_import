# -*- coding: utf-8 -*-
import re
import json, yaml
import pynetbox
import requests
from pprint import pprint
import logging
import sys
import ipaddress
from ipaddress import IPv4Network
import glob
import argparse
import time

# All specific info is written in yaml file
with open("config.yml", 'r', encoding="utf-8") as ymlfile:
    config = yaml.load(ymlfile, Loader=yaml.FullLoader)
# Arguments
parser = argparse.ArgumentParser()
parser.add_argument("-l", "--list_of_devices", required=True, help='Choices: "all" - all devices from ap folder; "device" - a single device by name; "site - a site')
parser.add_argument("-d", "--debug", required=False)
parser.add_argument("-v", "--virtual_machines", required=False, help='Choices: "yes" - update all VMs from ESXI')
args = parser.parse_args()
file_with_device = args.list_of_devices
debug_flag = args.debug
vm_update = args.virtual_machines


def logs_and_debug(debug_flag):
    # To view debug logs on a screen
    if debug_flag:
        stream = logging.StreamHandler(sys.stdout)
        stream.setLevel(logging.DEBUG)
        log = logging.getLogger()
        log.addHandler(stream)
        log.setLevel(logging.DEBUG)
    # To write debug logs into a text file
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)s %(message)s',
        filename='Log//LOGS.txt',
        filemode='w')


def create_or_update_vm_noc():
    from pyVim.connect import SmartConnect, SmartConnectNoSSL, Disconnect, vmodl, vim
    import ssl, logging, re
    import pynetbox
    import requests
    import dns, dns.resolver, dns.rdataclass, dns.rdatatype
    from pprint import pprint

    c = SmartConnectNoSSL(host=config['esxi.url'], user=config['esxi.username'], pwd=config['esxi.password'])
    datacenter = c.content.rootFolder.childEntity[0]
    noc_folder = datacenter.vmFolder.childEntity[0]
    virtual_machines = []
    vm_mac = None
    for vm in noc_folder.childEntity:
        if vm.guest.net:
            vm_mac = vm.guest.net[0].macAddress
        ans = dns.resolver.query(vm.name, rdtype=dns.rdatatype.A, rdclass=dns.rdataclass.IN)
        vm_ip = str(ans.rrset[0])
        if vm.guest.guestFullName:
            vm_os = vm.guest.guestFullName
        else:
            vm_os = 'Other'
        virtual_machines.append({'vm_name': vm.name, 'vm_ip': vm_ip, 'vm_mac': vm_mac, 'vm_os': vm_os})
    # Connecting to nb Server
    nb = netbox_connect()
    # Creating/Updating VMs in Netbox
    for noc_vm in virtual_machines:
        platform = nb.dcim.platforms.get(name=noc_vm['vm_os'])
        if platform is None:
            slug = noc_vm['vm_os'].lower().replace(' ', '_').replace('(', '_').replace(')', '_').replace('/', '_').replace('.', '_').replace('__', '_')
            platform = nb.dcim.platforms.create(name=noc_vm['vm_os'], slug=slug, manufacturer=12)
            print(str(time.asctime() + '  ' + 'No Platform ' + noc_vm['vm_os'] + ' ,the Platform is created').center(200, '-'))
        if noc_vm['vm_mac']:
            serial = noc_vm['vm_mac']
        else:
            serial = 'N/A'
        platform_id = platform.id
        device_get = nb.dcim.devices.get(name=noc_vm['vm_name'])
        if device_get is None:
            print(str(time.asctime() + '  ' + 'No VM ' + noc_vm['vm_name'] + ' Exists. Creating new VM').center(200, '-'))
            device_get = nb.dcim.devices.create(name=noc_vm['vm_name'], site=1, device_role=3, device_type=54, status='active', platform=platform_id, serial=serial)
        else:
            print(str('UPDATING VM ' + noc_vm['vm_name']).center(200, '-'))
            device_get.update({'serial': serial, 'site': 1, 'device_role': 3, 'device_type': 54, 'platform': platform_id})
        #
        # Interface mgmt
        interface_get = nb.dcim.interfaces.get(device_id=device_get.id, name='mgmt')
        if interface_get is None:
            interface_get = nb.dcim.interfaces.create(device=device_get.id, name='mgmt', type='virtual', enabled=True)
            print(str(time.asctime() + '  ' + 'New Interface "mgmt" is Created on VM ' + device_get.name).center(200, '-'))
        # IP Addresses
        ip_get = nb.ipam.ip_addresses.get(address=noc_vm['vm_ip'], interface_id=interface_get.id)
        if ip_get is None:
            ip_get = nb.ipam.ip_addresses.create(address=noc_vm['vm_ip'], assigned_object_type='dcim.interface', assigned_object_id=interface_get.id, status='active')
            print(str(time.asctime() + '  ' + 'New IP Address With Address ' + noc_vm['vm_ip'] + ' and ID ' + str(ip_get.id) + ' is Created on ' + interface_get.name).center(200, '-'))
        else:
            ip_get.update({'assigned_object_type': 'dcim.interface', 'assigned_object_id': interface_get.id})
            print(str(time.asctime() + '  ' + 'Existing IP Address ' + noc_vm['vm_ip'] + ' with ID ' + str(ip_get.id) + ' is Updated on ' + interface_get.name).center(200, '-'))
        device_get.update({'primary_ip4': ip_get})


def netbox_connect():
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    session = requests.Session()
    session.verify = False
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    nb = pynetbox.api(url=config['netbox.url'], token=config['netbox.token'])
    nb.http_session = session
    nb.http_session.verify = False
    return nb


def create_or_update_device(device_api_file_name):

    def adopting_device_values_for_netbox():
        # Manufacturer
        manufacturer = nb.dcim.manufacturers.get(name=device['MANUFACTURER'])
        if manufacturer is None:
            print(str(time.asctime() + '  ' + 'No Manufacturer ' + device['MANUFACTURER'] + ', the Manufacturer is created').center(200, '-'))
            manufacturer = nb.dcim.manufacturers.create(name=device['MANUFACTURER'], slug=device['MANUFACTURER'])
        manufacturer_id = manufacturer.id
        # Device Type
        device_type = nb.dcim.device_types.get(model=device['DEVICE_TYPE'])
        slug = device['DEVICE_TYPE']
        if device_type is None:
            chars = ['/', '+']
            for char in chars:
                if char in device['DEVICE_TYPE']:
                    slug = device['DEVICE_TYPE'].replace(char, '')
            device_type = nb.dcim.device_types.create(model=device['DEVICE_TYPE'], slug=slug, manufacturer=manufacturer_id, u_height=1)
            print(str(time.asctime() + '  ' + 'No model ' + device['DEVICE_TYPE'] + ' ,the Model is created').center(200, '-'))
        device_type_id = device_type.id
        # Device Role
        device_role = nb.dcim.device_roles.get(name=device['DEVICE_ROLE'])
        if device_role is None:
            device_role = nb.dcim.device_roles.create(name=device['DEVICE_ROLE'], slug=device['DEVICE_ROLE'].lower())
        #
        site = nb.dcim.sites.get(name=device['SITE'])
        if site is None:
            site = nb.dcim.sites.create(name=device['SITE'], slug=device['SITE'])
        # Platform
        platform = nb.dcim.platforms.get(name=device['DEVICE_PLATFORM'])
        if platform is None:
            slug = device['DEVICE_PLATFORM'].lower().replace(' ', '_')
            platform = nb.dcim.platforms.create(name=device['DEVICE_PLATFORM'], slug=slug, manufacturer=manufacturer_id, description=device['SOFTWARE'])
            print(str(time.asctime() + '  ' + 'No Platform ' + device['DEVICE_PLATFORM'] + ' ,the Platform is created').center(200, '-'))
        platform_id = platform.id
        #
        return device, name, device_type, device_type_id, device_role, site, platform_id, manufacturer_id

    def adopting_interface_values_for_netbox():
        hardware_types = {'EtherSVI': 'virtual', 'Tunnel': 'virtual', 'Loopback': 'virtual', 'C6k 10000Mb 802.3': '10gbase-t', 'C6k 1000Mb 802.3': '1000base-t', 'EtherChannel': 'lag',
                          'Port-Channel': 'lag', 'Gigabit Ethernet': '1000base-t', '100/1000/10000/25000 Ethernet': '25gbase-x-sfp28', '1000/10000/25000/40000/50000/100000 Ethernet': '100gbase-x-cfp',
                          'Ten Gigabit Ethernet': '10gbase-t', 'APM86XXX FastEthernet': '100base-tx', 'Fast Ethernet': '100base-tx', 'PowerPC FastEthernet': '100base-tx', 'Two Gigabit Ethernet': '2.5gbase-t',
                          'Twenty Five Gigabit Ethernet': '25gbase-x-sfp28', 'Forty Gigabit Ethernet': '40gbase-x-qsfpp', 'App-hosting Gigabit Ethernet': 'other', 'ISR4451-X-4x1GE': '1000base-t',
                          'ISR4431-X-4x1GE': '1000base-t', 'ISR4321-X-4x1GE': '1000base-t', 'ISR4321-2x1GE': '1000base-t', 'CN Gigabit Ethernet': '1000base-t', 'NIM-ES2-8': '1000base-t',
                          'EHWIC-4 Gigabit Ethernet': '1000base-t', 'NIM-ES2-4': '1000base-t', '100/1000/10000 Ethernet': '10gbase-t', '40000 Ethernet': '40gbase-x-qsfpp', 'ASR1001': '1000base-t',
                          'Aggregated Ethernet': 'lag', 'Null': 'virtual', 'TenGigE': '10gbase-t', '1000/10000/25000 Ethernet': '25gbase-x-sfp28', '40000/100000 Ethernet': '100gbase-x-cfp',
                          '1000/10000 Ethernet': '10gbase-t', 'ISR4331-3x1GE': '1000base-t', 'FastEthernet': '100base-tx', 'BCM1125 Internal MAC': '1000base-t', 'i82545': '100base-tx',
                          'PQ3_TSEC': '1000base-t', 'MV64460 Internal MAC': '1000base-t', 'EHWIC-8 Gigabit Ethernet': '1000base-t', 'Embedded Service Engine': 'virtual',
                          'RP management port': '1000base-t', 'Ethernet SVI': 'virtual', 'GigabitEthernet': '1000base-t', 'PowerPC405 FastEthernet': '100base-tx', 'GEChannel': 'virtual',
                          'VLAN': 'virtual', 'Management Ethernet': '1000base-t', '100/1000/10000/40000 Ethernet': '40gbase-x-qsfpp', 'NIM-2GE-CU-SFP': '1000base-t', 'RP': '1000base-t', 'SP': '1000base-t'}

        status = {'up': True, 'down': False, 'Up': True, 'Down': False}
        interface_type = 'virtual'
        interface_status = True
        mtu = None
        mac_address = None
        mode = None
        vrf = None
        vrf_id = None
        vrf_name = None
        acl_in = None
        acl_out = None
        description = ''
        description_ip_in = '[ACL in] is "None"'
        description_ip_out = '[ACL out] is "None"'

        # For Netbox > 3 Version only. We create Custom Fields for ACL in Netbox and write real ACL lists to each interface acl field and its description
        if 'INBOUND_ACL' in interface:
            if interface['INBOUND_ACL']:
                acl_in = interface['INBOUND_ACL']
                description_ip_in = '   [ACL in] is "' + interface['INBOUND_ACL'] + '"'
        if 'OUTGOING_ACL' in interface:
            if interface['OUTGOING_ACL']:
                acl_out = interface['OUTGOING_ACL']
                description_ip_out = '   [ACL out] is "' + interface['OUTGOING_ACL'] + '"'
        description_ip = description_ip_in + ' ----- ' + description_ip_out
        #
        if 'HARDWARE_TYPE' in interface:
            if interface['HARDWARE_TYPE']:
                if interface['HARDWARE_TYPE'] in hardware_types.keys():
                    interface_type = hardware_types[interface['HARDWARE_TYPE']]
        #
        if 'DESCRIPTION' in interface:
            if interface['DESCRIPTION']:
                description = interface['DESCRIPTION']
        #
        if 'PROTOCOL_STATUS' in interface:
            if interface['PROTOCOL_STATUS']:
                if interface['PROTOCOL_STATUS'] in status.keys():
                    interface_status = status[interface['PROTOCOL_STATUS']]
        #
        if 'MTU' in interface:
            if interface['MTU']:
                mtu = interface['MTU']
        #
        if 'MAC_ADDRESS' in interface:
            if interface['MAC_ADDRESS']:
                mac_address = interface['MAC_ADDRESS']
        #
        if 'VRF' in interface:
            if interface['VRF']:
                if interface['VRF'] == 'default':
                    vrf = None
                    vrf_id = None
                    vrf_name = None
                else:
                    for i in nb.ipam.vrfs.all():
                        if i.name != interface['VRF']:
                            continue
                        elif i.name == interface['VRF']:
                            vrf = i
                            vrf_id = vrf.id
                            vrf_name = vrf.name
                            break
                    if vrf is None:
                        print(str(time.asctime() + '  ' + 'No VRF ' + interface['VRF'] + ' ,new VRF is created').center(200, '-'))
                        vrf = nb.ipam.vrfs.create(name=interface['VRF'], enforce_unique='false')
                        vrf_id = vrf.id
                        vrf_name = vrf.name

        #
        if 'ADMIN_MODE' in interface:
            if 'access' in interface['ADMIN_MODE'] or 'dynamic auto' in interface['ADMIN_MODE']:
                mode = 'access'
            elif 'trunk' in interface['ADMIN_MODE'] and 'ALL' in interface['TRUNKING_VLANS']:
                mode = 'tagged-all'
            elif 'trunk' in interface['ADMIN_MODE'] and 'ALL' not in interface['TRUNKING_VLANS']:
                mode = 'tagged'
        #
        return site, interface, interface_type, interface_status, mtu, mac_address, vrf, vrf_id, vrf_name, mode, acl_in, acl_out, description_ip, description

    def create_update_interface():
        interface_get = nb.dcim.interfaces.get(device_id=device_get.id, name=interface['INTF'])
        if interface_get is None:
            interface_get = nb.dcim.interfaces.create(device=device_get.id, name=interface['INTF'], type=interface_type, description=description, mtu=mtu, mac_address=mac_address,
                                                      enabled=interface_status, mode=mode, acl_in=acl_in, acl_out=acl_out)
            print(str(time.asctime() + '  ' + 'New Interface ' + interface['INTF'] + ' is Created on Device ' + name).center(200, '-'))
        else:
            interface_get.update({'type': interface_type, 'description': description, 'enabled': interface_status, 'mtu': mtu, 'mac_address': mac_address, 'mode': mode})
            print(str(time.asctime() + '  ' + 'Interface ' + interface['INTF'] + ' on Device ' + name + ' is Updated').center(200, '-'))
        return interface_get

    def acl_on_interface():
        interface_get.custom_fields['acl_in'] = acl_in
        interface_get.save()
        interface_get.custom_fields['acl_out'] = acl_out
        interface_get.save()

    def vlans_on_interface():
        if mode:
            v_list = []
            if mode == 'tagged':
                if device['VLANS']:
                    for v in device['VLANS']:
                        for i in interface['TRUNKING_VLANS']:
                            if v['vlan_id'] != i:
                                continue
                            elif v['vlan_id'] == i:
                                vlan_id = v['vlan_id']
                                vlan_name = v['vlan_name']
                                if not nb.ipam.vlans.get(vid=vlan_id, name=vlan_name, site_id=site.id):
                                    nb.ipam.vlans.create(vid=vlan_id, name=vlan_name, site=site.id)
                                    print(str(time.asctime() + '  ' + 'VLAN "' + vlan_name + '" within SITE "' + v['site'] + '" is Created.').center(200, '-'))
                                v_list.append({'vid': vlan_id,
                                               'vlan_name': vlan_name,
                                               'id': nb.ipam.vlans.get(vid=vlan_id, name=vlan_name, site_id=site.id)})
                                break
                    if v_list:
                        interface_get.update({'tagged_vlans': [vl['id'] for vl in v_list]})
                        print(f'{time.asctime()} Tagged Vlans Updated on "{interface_get.name}" Device "{device_get.name}"'.center(200, '-'))
                else:
                    pass
            elif mode == 'access':
                if device['VLANS']:
                    for v in device['VLANS']:
                        if v['vlan_id'] != interface['ACCESS_VLAN']:
                            continue
                        elif v['vlan_id'] == interface['ACCESS_VLAN']:
                            vlan_id = v['vlan_id']
                            vlan_name = v['vlan_name']
                            if not nb.ipam.vlans.get(vid=vlan_id, name=vlan_name, site_id=site.id):
                                nb.ipam.vlans.create(vid=vlan_id, name=vlan_name, site=site.id)
                                print(str(time.asctime() + '  ' + 'VLAN "' + vlan_name + '" within SITE "' + v['site'] + '" is Created.').center(200, '-'))
                            break
                    interface_get.update({'untagged_vlan': nb.ipam.vlans.get(vid=vlan_id, name=vlan_name, site_id=site.id)})
                    print(f'{time.asctime()} Access Vlan Updated on "{interface_get.name}" Device "{device_get.name}"'.center(200, '-'))

    def etherchannel_setup():
        shortcuts = {'Gi': 'GigabitEthernet', 'Fa': 'FastEthernet', 'Twe': 'TwentyFiveGigE', 'Tw': 'TwoGigabitEthernet', 'Te': 'TenGigabitEthernet', 'Po': 'ort-channel', 'Eth': 'Ethernet',
                     'Fo': 'FortyGigabitEthernet'}
        if 'ETHERCHANNEL_MEMBERS' in interface and 'SG220' not in device_type.display:
            if interface['ETHERCHANNEL_MEMBERS']:
                if type(interface['ETHERCHANNEL_MEMBERS']) is list:
                    interface['ETHERCHANNEL_MEMBERS'] = ' '.join(interface['ETHERCHANNEL_MEMBERS'])
                if ',' in interface['ETHERCHANNEL_MEMBERS']:
                    interface['ETHERCHANNEL_MEMBERS'] = interface['ETHERCHANNEL_MEMBERS'].replace(',', '')
                if 'Etherneternet' in interface['ETHERCHANNEL_MEMBERS']:
                    interface['ETHERCHANNEL_MEMBERS'] = interface['ETHERCHANNEL_MEMBERS'].replace('Etherneternet', 'Ethernet')
                interface_get = nb.dcim.interfaces.get(device_id=device_get.id, name=interface['INTF'])
                ports = interface['ETHERCHANNEL_MEMBERS'].split()
                for z in range(len(ports)):
                    i = re.search('([A-zZ-a]+)\d', ports[z]).group(1)
                    if i in shortcuts.keys():
                        ports[z] = ports[z].replace(i, shortcuts[i])
                lag_interfaces.append({interface_get: [nb.dcim.interfaces.get(device_id=device_get.id, name=i) for i in ports]})
        if 'ETHERCHANNEL_MEMBERS' in interface and 'SG220' in device_type.display:
            if interface['ETHERCHANNEL_MEMBERS']:
                port_channel_name = 'Port-channel' + interface['ETHERCHANNEL_MEMBERS']
                lag_interfaces.append({port_channel_name: [interface_get]})
        return lag_interfaces

    def create_or_update_ip_addresses(vrf_id):
        # Gathering All IP Addresses to a List
        addresses = []
        ip_role = None
        if 'ANYCAST_GATEWAY' in interface:
            if interface['ANYCAST_GATEWAY'] == 'anycast-gateway':
                ip_role = 'anycast'
        if 'PRIMARY_IP_ADDRESS' in interface and interface['PRIMARY_IP_ADDRESS'] != []:
            for i in range(len(interface['PRIMARY_IP_ADDRESS'])):
                if interface['PRIMARY_IP_MASK']:
                    mask = interface['PRIMARY_IP_MASK'][i]
                else:
                    mask = '32'
                if 'SG220' in device_type.display or device_role.name == 'wlc':
                    if interface['PRIMARY_IP_MASK']:
                        mask = str(ipaddress.IPv4Network('0.0.0.0/' + interface['PRIMARY_IP_MASK'][i]).prefixlen)
                    else:
                        mask = '32'
                addresses.append({interface['PRIMARY_IP_ADDRESS'][i] + '/' + mask: ip_role})
        if 'SECONDARY_IP_ADDRESS' in interface and interface['SECONDARY_IP_ADDRESS'] != []:
            for i in range(len(interface['SECONDARY_IP_ADDRESS'])):
                addresses.append({interface['SECONDARY_IP_ADDRESS'][i] + '/' + interface['SECONDARY_IP_MASK'][i]: ip_role})
        if 'HSRP' in device and device['HSRP']:
            for hsrp in device['HSRP']:
                hsrp_ip = hsrp['VIRTUAL_IP'] + '/32'
                if hsrp['VIRTUAL_INTERFACE'] == interface['INTF']:
                    ip_role = 'hsrp'
                    addresses.append({hsrp_ip: ip_role})
        # Deleting stale ip and its prefix if exists on interface
        for stale_ip in nb.ipam.ip_addresses.filter(interface_id=interface_get.id):
            if not any(stale_ip.address in ip_dict for ip_dict in addresses):
                stale_prefix = str(ipaddress.ip_network(stale_ip.address, False))
                stale_prefix_get = nb.ipam.prefixes.get(prefix=stale_prefix, vrf_id=vrf_id, site_id=site.id)
                stale_ip.delete()
                stale_prefix_get.delete()
                print(str(time.asctime() + '  ' + 'Stale IP Address "' + stale_ip.address + '" and its Prefix "' + stale_prefix + '" Deleted on Interface ' + interface['INTF']).center(200, '-'))
        for ip in addresses:
            # Creating/updating primary ip
            for key, value in ip.items():
                if vrf_id == 'null':
                    vrf_id = None
                ip_get = nb.ipam.ip_addresses.get(address=key, interface_id=interface_get.id, vrf_id=vrf_id)
                if ip_get is None:
                    ip_get = nb.ipam.ip_addresses.create(address=key, assigned_object_type='dcim.interface', assigned_object_id=interface_get.id, status='active', vrf=vrf_id, description=description_ip, role=value)
                    print(str(time.asctime() + '  ' + 'New IP Address With Address ' + key + ' and ID ' + str(ip_get.id) + ' is Created on ' + interface['INTF']).center(200, '-'))
                else:
                    ip_get.update({'assigned_object_type': 'dcim.interface', 'assigned_object_id': interface_get.id, 'vrf': vrf_id, 'description': description_ip, 'role': value})
                    print(str(time.asctime() + '  ' + 'Existing IP Address ' + key + ' with ID ' + str(ip_get.id) + ' is Updated on ' + interface['INTF']).center(200, '-'))
                # Creating Prefixes
                if value != 'hsrp':
                    netbox_vrf_name = 'Global'
                    if vrf_id != None:
                        netbox_vrf_name = vrf_name
                    else:
                        vrf_id = 'null'
                    prefix = str(ipaddress.ip_network(key, False))
                    prefix_get = nb.ipam.prefixes.get(prefix=prefix, vrf_id=vrf_id, site_id=site.id)
                    try:
                        dot1q_sub_interface_search = re.search('^\S+\.(\d+)$', ip_get.assigned_object.name)
                        dot1q_sub_interface = dot1q_sub_interface_search.group(0)
                        dot1q_sub_interface_vlan = dot1q_sub_interface_search.group(1)
                    except:
                        dot1q_sub_interface = 'NONE'
                        dot1q_sub_interface_vlan = 'NONE'
                        pass
                    if prefix_get:
                        if ('Vlan' in ip_get.assigned_object.name or dot1q_sub_interface in ip_get.assigned_object.name) and ('ASW' not in ip_get.assigned_object.device.name):
                            description_devices = str(' ----- [Devices] : "' + ip_get.assigned_object.device.name + '"')
                            if dot1q_sub_interface != 'NONE':
                                description_vlan = f'[VLAN] : "Vlan{dot1q_sub_interface_vlan}"'
                            else:
                                description_vlan = str('[VLAN] : "' + ip_get.assigned_object.name + '"')
                            if '[Devices]' not in prefix_get.description:
                                prefix_get.update({'description': description_vlan + description_devices})
                            elif '[Devices]' in prefix_get.description and ip_get.assigned_object.device.name not in prefix_get.description:
                                try:
                                    prefix_get.update({'description': prefix_get.description + ' , "' + ip_get.assigned_object.device.name + '"'})
                                except Exception as error:
                                    error_string = str(error)
                                    if "{'description': ['Ensure this field has no more than 200 characters.']}" in error_string:
                                        prefix_get.description = prefix_get.description.replace(str('"' + ip_get.assigned_object.device.name + '"'), '')
                                        pass
                        print(str(time.asctime() + '  ' + 'Existing Prefix ' + prefix + ' in VRF "' + netbox_vrf_name + '" Within Site "' + site.name + '" is Updated').center(200, '-'))
                    else:
                        if vrf_id == 'null':
                            vrf_id = None
                        if 'Vlan' in ip_get.assigned_object.name and 'ASW' not in ip_get.assigned_object.device.name:
                            description_vlan = str('[VLAN] : "' + ip_get.assigned_object.name + '"')
                            description_devices = str(' ----- [Devices] : "' + ip_get.assigned_object.device.name + '"')
                            prefix_get = nb.ipam.prefixes.create(prefix=prefix, is_pool=False, vrf=vrf_id, site=site.id, status='active', description=description_vlan + description_devices)
                        elif 'Vlan' not in ip_get.assigned_object.name:
                            prefix_get = nb.ipam.prefixes.create(prefix=prefix, is_pool=False, vrf=vrf_id, site=site.id, status='active',
                                                                 description=ip_get.assigned_object.device.name + ' ----- ' + ip_get.assigned_object.name)
                        print(str('Prefix ' + prefix + ' in VRF "' + netbox_vrf_name + '" Within Site "' + site.name + '" Does Not Exist. Creating New Prefix').center(200, '-'))
                    if acl_in:
                        prefix_get.custom_fields['acl_inbound'] = acl_in
                        prefix_get.save()
                    if acl_out:
                        prefix_get.custom_fields['acl_outgoing'] = acl_out
                        prefix_get.save()

    def stale_interfaces_clean_up():
        actual_interfaces = []
        for interface in device['INTERFACES']:
            if 'INTF' in interface and interface['INTF'] != []:
                actual_interfaces.append(interface['INTF'])
        for intf in nb.dcim.interfaces.filter(device_id=device_get.id):
            if intf.name not in actual_interfaces:
                stale_interface = nb.dcim.interfaces.get(device_id=device_get.id, name=intf.name)
                if nb.ipam.ip_addresses.filter(interface_id=stale_interface.id):
                    for stale_ip in nb.ipam.ip_addresses.filter(interface_id=stale_interface.id):
                        vrf = None
                        if stale_ip.vrf:
                            vrf = stale_ip.vrf.id
                        stale_prefix = str(ipaddress.ip_network(stale_ip.address, False))
                        stale_prefix_get = nb.ipam.prefixes.get(prefix=stale_prefix, vrf_id=vrf, site_id=site.id)
                        stale_ip.delete()
                        if stale_prefix_get:
                            stale_prefix_get.delete()
                        print(str(time.asctime() + '  ' + 'Stale IP Address "' + stale_ip.address + '" and its Prefix "' + stale_prefix + '" Deleted on Interface ' + intf.name).center(200, '-'))
                stale_interface.delete()
                print(str(time.asctime() + '  ' + 'Stale Interface "' + intf.name + '" Deleted on Device ' + name).center(200, '-'))

    def prefix_to_vlan_binding():
        if 'VLANS' in device.keys():
            if device['VLANS']:
                for vlan in device['VLANS']:
                    vl_name = vlan['vlan_name']
                    vlan_get = nb.ipam.vlans.get(site_id=site.id, name=vlan['vlan_name'], vid=vlan["vlan_id"])
                    if vlan_get:
                        if vlan['vrf'] != '' and vlan['vrf'] != 'default':
                            vrf_get = nb.ipam.vrfs.get(name=vlan['vrf'])
                            vrf_get_id = vrf_get.id
                        else:
                            vrf_get_id = 'null'
                        # Binding Primary Prefixes to Vlans
                        if vlan['vlan_primary_prefixes']:
                            for prefix in vlan['vlan_primary_prefixes']:
                                vlan_prefix = nb.ipam.prefixes.filter(prefix=prefix, vrf_id=vrf_get_id, site_id=site.id)
                                for i in vlan_prefix:
                                    if vlan["vlan_id"] in i.description:
                                        vlan_prefix = i
                                        if vlan_prefix:
                                            vlan_prefix.vlan = vlan_get.id
                                            vlan_prefix.save()
                                            print(str(time.asctime() + '  ' + 'VLAN ID - "' + vlan["vlan_id"] + '" (' + vl_name + ') within SITE "' + vlan['site'] + '" is Binded to Prefix "' + vlan_prefix.prefix + '"').center(200, '-'))
                        # Binding Secondary Prefixes to Vlans
                        if vlan['vlan_secondary_prefixes']:
                            for prefix in vlan['vlan_secondary_prefixes']:
                                vlan_prefix = nb.ipam.prefixes.filter(prefix=prefix, vrf_id=vrf_get_id, site_id=site.id)
                                for i in vlan_prefix:
                                    if vlan["vlan_id"] in i.description:
                                        vlan_prefix = i
                                        if vlan_prefix:
                                            vlan_prefix.vlan = vlan_get.id
                                            vlan_prefix.save()
                                            print(str(time.asctime() + '  ' + 'VLAN ID - "' + vlan["vlan_id"] + '" (' + vl_name + ') within SITE "' + vlan['site'] + '" is Binded to Prefix "' + vlan_prefix.prefix + '"').center(200, '-'))

    def interface_to_lag_binding():
        for i in lag_interfaces:
            for key, value in i.items():
                for q in value:
                    if 'SG220' in device_type.display:
                        lag_interface = nb.dcim.interfaces.get(device_id=device_get.id, name=key)
                        q.lag = lag_interface.id
                    else:
                        q.lag = key.id
                    q.save()

    def create_or_update_connections():
        # First, Deleting all existing connections. Stale connections are removed and actual connections will be added again
        for cable in nb.dcim.cables.filter(device=device_get.name):
            if cable.termination_a_type == 'circuits.circuittermination' or cable.termination_b_type == 'circuits.circuittermination':
                continue
            else:
                cable.delete()
        #
        if 'CONNECTIONS' in device.keys():
            if device['CONNECTIONS']:
                for connection in device['CONNECTIONS']:
                    # Checking if the Device Exists in NETBOX
                    if connection['INTERFACE_A'] != '' and connection['INTERFACE_B'] != '':
                        device_b = nb.dcim.devices.get(name=connection['DEVICE_B'])
                        if device_b is None:
                            print(str(time.asctime() + '  ' + 'Device "' + connection['DEVICE_B'] + '" Does Not Exist in NETBOX').center(200, '-'))
                        else:
                            termination_a_get = nb.dcim.interfaces.get(name=connection['INTERFACE_A'], device=device_get.name)
                            termination_b_get = nb.dcim.interfaces.get(name=connection['INTERFACE_B'], device=device_b)
                            if termination_a_get and termination_b_get:
                                try:
                                    nb.dcim.cables.create(termination_a_type='dcim.interface', termination_a_id=termination_a_get.id, termination_b_type='dcim.interface', termination_b_id=termination_b_get.id)
                                    print(str(time.asctime() + '  ' + 'Connection Between "' + device_get.name + '" and "' + device_b.name + '" is Created/Updated').center(200, '-'))
                                except:
                                    pass

    def create_or_update_inventory():
        # Deleting Existing Items
        try:
            inventory_items = nb.dcim.inventory_items.filter(device_id=device_get.id)
            for inventory_item in inventory_items:
                inventory_item.delete()
        except:
            pass
        #
        if 'INVENTORY' in device.keys():
            if device['INVENTORY']:
                for inv in device['INVENTORY']:
                    try:
                        inventory_item = nb.dcim.inventory_items.create(name=inv['NAME'], device=device_get.id, description=inv['DESCRIPTION'], part_id=inv['PID'], serial=inv['SN'])
                        print(str(time.asctime() + '  ' + 'Inventory Item "' + inv['SN'] + '" is Created/Updated on Device ' + device_get.name).center(200, '-'))
                    except Exception as error:
                        error_string = str(error)
                        if "Ensure this field has no more than 64 characters" in error_string:
                            inventory_item_name = inv['PID']
                            try:
                                inventory_item = nb.dcim.inventory_items.create(name=inventory_item_name, device=device_get.id, description=inv['DESCRIPTION'], part_id=inv['PID'], serial=inv['SN'])
                                print(str(time.asctime() + '  ' + 'Inventory Item "' + inv['DESCRIPTION'] + '" is Created/Updated on Device ' + device_get.name).center(200, '-'))
                            except:
                                pass

    def cisco_wlc_access_points_and_wlans():
        if 'WLANS' in device:
            for wlan in device['WLANS']:
                wlan_group = nb.wireless.wireless_lan_groups.get(name=site.name)
                wlan_interface = nb.dcim.interfaces.get(name=wlan['INTERFACE'], device_id=device_get.id)
                wlan_interface_ip = nb.ipam.ip_addresses.get(interface_id=wlan_interface.id)
                wlan_prefix = nb.ipam.prefixes.get(q=wlan_interface_ip.address, site_id=site.id, vrf='null')
                wlan_vlan = wlan_prefix.vlan
                wlan_get = nb.wireless.wireless_lans.get(ssid=wlan['SSID'], group_id=wlan_group.id)
                if not wlan_get:
                    wlan_get = nb.wireless.wireless_lans.create(ssid=wlan['SSID'], group=wlan_group.id, vlan=wlan_vlan.id)
                    print(str(time.asctime() + '  ' + 'New SSID ' + wlan['SSID'] + ' on Controller ' + device_get.name + ' is Created').center(200, '-'))
                else:
                    wlan_get.update({'group': wlan_group.id, 'vlan': wlan_vlan.id})
                    print(str(time.asctime() + '  ' + 'SSID ' + wlan['SSID'] + ' on Controller ' + device_get.name + ' is Updated').center(200, '-'))
        if 'AP' in device:
            if device['AP']:
                for ap in device['AP']:
                    name = ap['AP_NAME']
                    ap_type = None
                    ap_platform = None
                    ap_role = None
                    #
                    ap_type = nb.dcim.device_types.get(model=ap['AP_MODEL'])
                    if ap_type is None:
                        chars = ['/', '+']
                        for c in chars:
                            if c in ap['AP_MODEL']:
                                slug = ap['AP_MODEL'].replace(c, '')
                            else:
                                slug = ap['AP_MODEL']
                        ap_type = nb.dcim.device_types.create(model=ap['AP_MODEL'], slug=slug, manufacturer=manufacturer_id, u_height=1)
                        print(str(time.asctime() + '  ' + 'No model ' + ap['AP_MODEL'] + ' ,the Model is created').center(200, '-'))
                    ap_type_id = ap_type.id
                    #
                    ap_role = nb.dcim.device_roles.get(name='ap')
                    if ap_role is None:
                        ap_role = nb.dcim.device_roles.create(name='ap', slug='ap')
                    #
                    ap_platform = nb.dcim.platforms.get(name=ap['AP_PLATFORM'])
                    ap_slug = ap['AP_PLATFORM'].lower()
                    if ap_platform is None:
                        chars = ['/', '+', '(', ')', ' ', '.']
                        for c in chars:
                            if c in ap_slug:
                                ap_slug = ap_slug.replace(c, '_')
                        ap_platform = nb.dcim.platforms.create(name=ap['AP_PLATFORM'], slug=ap_slug, manufacturer=manufacturer_id, description=ap['AP_PLATFORM'])
                        print(str('No Platform ' + ap['AP_PLATFORM'] + ' ,the Platform is created').center(200, '-'))
                    ap_platform_id = ap_platform.id
                    #
                    ap_get = nb.dcim.devices.get(name=name)
                    if ap_get is None:
                        ap_get = nb.dcim.devices.create(name=name, site=site.id, device_role=ap_role.id, device_type=ap_type_id, status='active', platform=ap_platform_id, serial=ap['AP_SN'])
                        print(str(time.asctime() + '  ' + 'No AP ' + name + ' Exists. Creating new AP').center(200, '-'))
                    else:
                        ap_get.update({'serial': ap['AP_SN'], 'site': site.id, 'device_role': ap_role, 'device_type': ap_type_id, 'platform': ap_platform_id})
                        print(str(time.asctime() + '  ' + 'UPDATING AP ' + name).center(200, '-'))
                    #
                    # Creating AP interfaces
                    ap_interface_get = nb.dcim.interfaces.get(device_id=ap_get.id, name=ap['AP_INTERFACE'])
                    if ap_interface_get is None:
                        ap_interface_get = nb.dcim.interfaces.create(device=ap_get.id, name=ap['AP_INTERFACE'], type='1000base-t', mac_address=ap['AP_MAC'], enabled=True)
                        print(str(time.asctime() + '  ' + 'New Interface ' + ap['AP_INTERFACE'] + ' is Created on Device ' + name).center(200, '-'))
                    #
                    if ap['AP_IP']:
                        ap_prefix_get = nb.ipam.prefixes.get(q=ap['AP_IP'], site_id=site.id, vrf='null')
                        ap_ip_mask = str(re.search('\d+.\d+.\d+.\d+(\/\d+)', ap_prefix_get.prefix).group(1))
                        ap_ip = ap['AP_IP'][0] + ap_ip_mask
                        ap_ip_get = nb.ipam.ip_addresses.get(address=ap_ip, interface_id=ap_interface_get.id)
                        if ap_ip_get is None:
                            ap_ip_get = nb.ipam.ip_addresses.create(address=ap_ip, assigned_object_type='dcim.interface', assigned_object_id=ap_interface_get.id, status='active')
                            print(str(time.asctime() + '  ' + 'New IP Address With Address ' + ap_ip + ' and ID ' + str(ap_ip_get.id) + ' is Created on ' + ap_interface_get.name).center(200, '-'))
                        else:
                            ap_ip_get.update({'assigned_object_type': 'dcim.interface', 'assigned_object_id': ap_interface_get.id})
                            print(str('Existing IP Address ' + ap_ip + ' with ID ' + str(ap_ip_get.id) + ' is Updated on ' + ap_interface_get.name).center(200, '-'))
                        try:
                            ap_get.update({'primary_ip4': ap_ip_get})
                        except:
                            pass
    # Loading a device dict from a json file
    with open(device_api_file_name) as json_file:
        device_list = json.load(json_file)

    # Connecting to nb Server
    nb = netbox_connect()

    for device in device_list:
        name = device['DEVICE_NAME']

        # Preparing device variables for Netbox API
        device, name, device_type, device_type_id, device_role, site, platform_id, manufacturer_id = adopting_device_values_for_netbox()

        # Creating/Updating a device
        device_get = nb.dcim.devices.get(name=name)
        if device_get is None:
            print(str(time.asctime() + '  ' + 'No Device ' + name + ' Exists. Creating new Device').center(200, '-'))
            nb.dcim.devices.create(name=name, site=site.id, device_role=device_role.id, device_type=device_type_id, status='active', platform=platform_id, serial=device['SERIAL_NUMBER'])
            device_get = nb.dcim.devices.get(name=name)
        else:
            print(str(time.asctime() + '  ' + 'UPDATING DEVICE ' + name).center(200, '-'))
            device_get.update({'serial': device['SERIAL_NUMBER'], 'site': site.id, 'device_role': device_role, 'device_type': device_type_id, 'platform': platform_id})
        lag_interfaces = []
        for interface in device['INTERFACES']:
            if 'PROTOCOL_STATUS' not in interface:
                interface['PROTOCOL_STATUS'] = 'up'
            if 'PROTOCOL_STATUS' in interface:
                # Preparing interface variables for Netbox API
                site, interface, interface_type, interface_status, mtu, mac_address, vrf, vrf_id, vrf_name, mode, acl_in, acl_out, description_ip, description = adopting_interface_values_for_netbox()
                # Creating/Updating interface
                interface_get = create_update_interface()
                # Adding ACLs to Interface
                acl_on_interface()
                # Adding Vlans
                vlans_on_interface()
                # Gathering LAGs Interfaces
                lag_interfaces = etherchannel_setup()
                # Creating ip addresses
                create_or_update_ip_addresses(vrf_id)

        # Deleting stale interfaces from device
        stale_interfaces_clean_up()

        # Binding Physical Interfaces to LAGs
        interface_to_lag_binding()

        # Binding Prefixes to Vlans
        prefix_to_vlan_binding()

        # Assign primary IP to a device
        # Unfortunately each device can have different management interface name and its impossible to create dependencies between device role and its management interface name
        management_interface_name = None
        if management_interface_name is not None:
            try:
                device_management_interface = nb.dcim.interfaces.get(device_id=device_get.id, name=management_interface_name)
                ip_v4 = nb.ipam.ip_addresses.get(device_id=device_get.id, interface_id=device_management_interface.id)
                device_get.update({'primary_ip4': ip_v4})
            except:
                pass
        # Updating Connections
        create_or_update_connections()

        # Updating Inventory
        create_or_update_inventory()

        # If its a WLC, create/update APs
        if device_role.name == 'wlc':
            cisco_wlc_access_points_and_wlans()
        print(str(time.asctime() + '  ' + 'DEVICE ' + device['DEVICE_NAME'] + ' WAS CREATED/UPDATED IN NETBOX').center(200, '-'))

#########################################################################################################################################################################################################################
failed_list = []
if file_with_device == 'all':
    for file in glob.glob("api/*.csv"):
        try:
            create_or_update_device(file)
        except:
            failed_list.append(file)
            pass
    if vm_update == 'yes':
        create_or_update_vm_noc()
    print('\n')
    print('#' * 300)
    if not failed_list:
        print(str(time.asctime() + '  ' + 'All Devices Have Been Updated Successfully. No Errors Detected').center(200, ' '))
    else:
        for d in failed_list:
            pprint(str(time.asctime() + '  ' + 'Something Went Wrong Updating/Creating Device  ----  ' + d).center(200, '-'))
elif file_with_device == 'site':
    site_name = input('Input a Site Name: ')
    site_devices = []
    for file in glob.glob("api/*.csv"):
        if site_name in file:
            site_devices.append(file)
    for device in site_devices:
        try:
            create_or_update_device(device)
        except:
            failed_list.append(device)
            pass
    if vm_update == 'yes':
        create_or_update_vm_noc()
    print('\n')
    print('#' * 200)
    if not failed_list:
        print(str(time.asctime() + '  ' + '__All Devices Have Been Updated Successfully. No Errors Detected__').center(200, '#'))
    else:
        for d in failed_list:
            print(str(time.asctime() + '  ' + 'Something Went Wrong Updating/Creating Device  ----  ' + d).center(50, '-'))
elif file_with_device == 'device':
    device_file_name = input('Input a Device Name: ')
    create_or_update_device('api//' + device_file_name + '.csv')
    if vm_update == 'yes':
        create_or_update_vm_noc()
