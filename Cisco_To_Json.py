# Script works fine with IOS, NX-OS, XR, SG-220, Air-OS.
# Caution! Script might fail trying to connect to some devices ,especially when connecting to more than 10 devices simultaneously in a thread.
# This script worked fine and was tested in one Enterprise network environment only, and some templates were edited to work in that environment.

import argparse
import collections
import ipaddress
import json
import logging
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import closing
from atlassian.confluence import Confluence
import html_to_json
import paramiko
import textfsm
import yaml
from netmiko import ConnectHandler, SSHDetect
from paramiko_expect import SSHClientInteraction
from tabulate import tabulate
from pprint import pprint

# All specific info is written in yaml file
with open("config.yml", 'r', encoding="utf-8") as ymlfile:
    config = yaml.load(ymlfile, Loader=yaml.FullLoader)
    # Maximum number of ssh conections
    limit = config['limit']
# Arguments
parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", required=True, help='Choices: "all" - from ip_list_all.txt file; "confluence" - from confluence page; "test" - from ip_list.txt file')
parser.add_argument("-d", "--debug", required=False)
args = parser.parse_args()
file_with_ip_addresses = args.file
debug_flag = args.debug

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
logs_and_debug(debug_flag)

# These lists gather info if something goes wrong
unable_to_login_by_ssh_ip_list = []
authentication_failed_list = []


# Connecting to Confluence page and getting ip list of all devices to connect by SSH
def confluence():
    username = config['confluence.username']
    password = config['confluence.password']
    confluenceBaseUrl = config['confluence.url']
    pageId = config['confluence.pageid']
    #
    ip_list_all = []
    try:
        confluence = Confluence(url=confluenceBaseUrl, username=username, password=password)
        page = confluence.get_page_by_id(page_id=pageId, expand='body.storage').get('body').get('storage').get('value')
        output_json = html_to_json.convert_tables(page)
        for device_dict in output_json[0]:
            ip_address = re.search('\d+\.\d+\.\d+\.\d+', device_dict['IP']).group(0)
            ip_list_all.append(ip_address)
    except:
        print('SOMETHING WENT WRONG GETTING INFO FROM CONFLUENCE PAGE'.center(200, '!'))
    return ip_list_all


# After we got ip list to connect we check each ip for 22 port is open making new reachable ip list
def connect_list(list_ipaddr):
    list_reachable_devices = []
    list_closed_ssh_port = []
    for item in list_ipaddr:
        # Check if the 22 port is open on a device
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            if sock.connect_ex((item, 22)) == 0:
                list_reachable_devices.append(item)
            else:
                print(str('PORT "22" IS CLOSED ON A DEVICE - ' + item).center(200, '-'))
                list_closed_ssh_port.append(item)
                unable_to_login_by_ssh_ip_list.append(item)
    return True, list_reachable_devices, list_closed_ssh_port


# For each reachable ip we create a dictionary preparing it for connection by Netmiko
def device_dictionary(list_ipaddr_dev):
    username = config['ssh.username']
    password = config['ssh.password']
    # Compiling dictionary of devices
    list_dic_devices = []
    for item in list_ipaddr_dev:
        list_dic_devices.append({'device_type': 'autodetect', 'ip': item, 'username': username, 'password': password, 'fast_cli': False})
    return True, list_dic_devices


# Connecting to device by SSH
def send_command_and_get_output(list_dic_devices, command, limit=limit):
    def send_commands(dic_command, dic_device):

        def netmiko_get_device_type():
            guesser = SSHDetect(timeout=10, **dic_device)
            best_match = guesser.autodetect()
            if best_match:
                dic_device['device_type'] = best_match
            if best_match == 'cisco_wlc':
                dic_device['device_type'] = 'cisco_wlc_ssh'
            return dic_device['device_type']

        def paramiko_get_device_type():
            result = None
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=dic_device['ip'], username=dic_device['username'], password=dic_device['password'], timeout=10)
            with client.invoke_shell() as ssh:
                ssh.send('show version\n')
                time.sleep(10)
                result = ssh.recv(1000).decode('utf-8')
                ssh.close()
            return result

        def paramiko_expect_get_device_type():
            result = None
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(hostname=dic_device['ip'], username=dic_device['username'], password=dic_device['password'])
            except:
                client.get_transport().auth_none(dic_device['username'])
                interact = SSHClientInteraction(client, timeout=10, display=False)
                #
                interact.expect('Username:.*')
                interact.send(dic_device['username'])
                interact.expect('.*:.*')
                username_failed = interact.current_output
                if '% Authentication Failed' in username_failed:
                    client.close()
                    auth_failed_flag = True
                    return result, auth_failed_flag
                else:
                    interact.send(dic_device['password'])
                    prompt = interact.expect(['.*:.*', '.*#'])
                    if prompt == 0:
                        password_failed = interact.current_output
                        if '% Authentication Failed' in password_failed:
                            client.close()
                            auth_failed_flag = True
                            return result, auth_failed_flag
                    else:
                        if prompt == 1:
                            #interact.expect('.*#')
                            interact.send('show version')
                            interact.expect('.*#')
                            result = interact.current_output
                            interact.send('exit')
                            interact.expect('.*>')
                            interact.send('exit')
                            client.close()
                            auth_failed_flag = False
                            return result, auth_failed_flag

        def ssh_get_device_type():
            # An attempt to understand what kind of device we are connecting to. For the first attempt we will use Netmiko
            try:
                dic_device['device_type'] = netmiko_get_device_type()
            except Exception as e:
                result = None
                if 'Authentication failed' not in str(e):
                    print(str('NETMIKO AUTODETECT DOESNT WORK ON THE DEVICE ' + dic_device['ip'] + ' , TRYING PARAMIKO').center(200, '-'))
                    # We are trying to determine the type by Paramiko
                    time.sleep(5)
                    try:
                        result = paramiko_get_device_type()
                    except:
                        print(f'Login on Device {dic_device["ip"]} Was Successful, But no Result From "show version" Command')
                        return {'ip': dic_device['ip'], 'output': None, 'device_type': None}
                elif 'Authentication failed' in str(e):
                    # Authentication failed. But this can be SG-220, we try it out with Expect and Paramiko
                    try:
                        result, auth_failed_flag = paramiko_expect_get_device_type()
                        if auth_failed_flag:
                            unable_to_login_by_ssh_ip_list.append(dic_device['ip'])
                            authentication_failed_list.append(dic_device['ip'])
                            return {'ip': dic_device['ip'], 'output': None, 'device_type': None}
                            pass
                    except:
                        print('PARAMIKO_EXPECT FAILED TO GET OUTPUT FROM DEVICE'.center(200, '!'))
                        unable_to_login_by_ssh_ip_list.append(dic_device['ip'])
                        authentication_failed_list.append(dic_device['ip'])
                        return {'ip': dic_device['ip'], 'output': None, 'device_type': None}
                        pass
                # Result is output from "show version" command by Paramiko in case Netmiko had failed
                if result:
                    if 'XR' in result:
                        dic_device['device_type'] = 'cisco_xr'
                    elif 'Cisco IOS' in result:
                        dic_device['device_type'] = 'cisco_ios'
                    elif 'NX-OS' in result:
                        dic_device['device_type'] = 'cisco_nxos'
                    elif 'Cisco Controller' in result:
                        dic_device['device_type'] = 'cisco_wlc_ssh'
                    elif 'SG220' in result:
                        dic_device['device_type'] = 'cisco_s200'
                    elif 'image_tesla_hybrid' in result:
                        dic_device['device_type'] = 'cisco_s350'
            return dic_device['device_type']

        def netmiko_send_command_cisco_wlc(command_list):
            command_result = {}
            with ConnectHandler(timeout=10, **dic_device) as ssh:
                find_hostname = ssh.send_command('show sysinfo')
                find_hostname = re.search('System Name\S+\.\s+(\S+)', find_hostname).group(1)
                interfaces = ssh.send_command('show interface summary')
                interface_names = re.findall('(\S+)\s+\S+\s+\S+\s+\d+\.', interfaces)
                result_1 = ''
                for interface in interface_names:
                    interface_result = ssh.send_command('show interface detailed ' + interface)
                    interface_result = interface_result.strip()
                    result_1 = result_1 + '\n' + interface_result
                command_result.update({'show interface detailed': result_1})
                time.sleep(2)
                for command in command_list:
                    result_2 = ssh.send_command(command, read_timeout=50)
                    result_2 = result_2.strip()
                    time.sleep(2)
                    command_result.update({command: result_2})
                ssh.disconnect()
            return find_hostname, command_result

        def netmiko_send_command_sg_220(command_list):
            command_result = {}
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(hostname=dic_device['ip'], username=dic_device['username'], password=dic_device['password'])
            except:
                client.get_transport().auth_none(dic_device['username'])
                interact = SSHClientInteraction(client, timeout=10, display=False)
                #
                interact.expect('Username: ')
                if interact.last_match == 'Username: ':
                    interact.send(dic_device['username'])
                #
                interact.expect('Password: ')
                if interact.last_match == 'Password: ':
                    interact.send(dic_device['password'])
                #
                interact.expect('.*#')
                result_for_hostname = interact.current_output
                find_hostname = re.search('(\S+)#', result_for_hostname).group(1)
                interact.send('terminal length 0')
                interact.expect('.*#')
                for command in command_list:
                    interact.send(command)
                    interact.expect('.*#', timeout=30)
                    result = interact.current_output
                    result = result.strip()
                    command_result.update({command: result})
                interact.send('exit')
                interact.expect('.*>')
                interact.send('exit')
            return find_hostname, command_result

        def netmiko_send_command_cisco_xr(command_list):
            command_result = {}
            with ConnectHandler(timeout=10, **dic_device) as ssh:
                find_hostname = ssh.find_prompt()
                chars = ['RP/0/RSP0/CPU0:', '>', '#']
                for c in chars:
                    if c in find_hostname:
                        find_hostname = find_hostname.replace(c, '')
                        find_hostname = find_hostname.strip()
                time.sleep(2)
                for command in command_list:
                    result_2 = ssh.send_command(command, read_timeout=50)
                    result_2 = result_2.strip()
                    time.sleep(2)
                    command_result.update({command: result_2})
                # For TenGig Interfaces Only
                interfaces = ssh.send_command('show interface brief | i Te')
                interface_names = re.findall("\s+(Te\S+)\s+", interfaces)
                result_1 = ''
                for interface in interface_names:
                    interface_result = ssh.send_command(f'show controllers {interface} phy | in Vendor')
                    interface_result = f'{interface}\n' + interface_result.strip()
                    result_1 = result_1 + '\n' + interface_result
                command_result.update({'show controllers interface': result_1})
                ssh.disconnect()
            return find_hostname, command_result

        def netmiko_send_command_cisco_common(command_list):
            command_result = {}
            with ConnectHandler(timeout=10, **dic_device) as ssh:
                if ssh.check_config_mode == False:
                    ssh.enable()
                for command in command_list:
                    result = ssh.send_command(command, read_timeout=50)
                    result = result.strip()
                    command_result.update({command: result})
                # Determine the host name for devices
                find_hostname = ssh.find_prompt()
                if '>' in find_hostname:
                    find_hostname = find_hostname.replace('>', '')
                elif '#' in find_hostname:
                    find_hostname = find_hostname.replace('#', '')
                find_hostname = find_hostname.strip()
                ssh.disconnect()
            return find_hostname, command_result

        dic_device['device_type'] = ssh_get_device_type()
        time.sleep(3)
        #
        if dic_device['device_type']:
            if dic_device['device_type'] != 'autodetect':
                # Connecting to device by Netmiko, sending command and getting output
                try:
                    command_list = dic_command[dic_device['device_type']]
                except Exception as e:
                    if 'KeyError' not in str(e):
                        print(f'THERE IS NO COMMANDS DICTIONARY ADDED FOR DEVICE TYPE "{dic_device["device_type"]}" . ADD NEW DICT TO "dic_command" VARIABLE'.center(200, '!'))
                        return ({'ip': dic_device['ip'], 'output': None, 'device_type': dic_device['device_type']})
                if dic_device['device_type'] == 'cisco_wlc_ssh':
                    try:
                        find_hostname, command_result = netmiko_send_command_cisco_wlc(command_list)
                        return {'ip': dic_device['ip'], 'output': command_result, 'hostname': find_hostname, 'device_type': dic_device['device_type']}
                    except:
                        return ({'ip': dic_device['ip'], 'output': None, 'device_type': dic_device['device_type']})
                elif dic_device['device_type'] == 'cisco_s200':
                    try:
                        find_hostname, command_result = netmiko_send_command_sg_220(command_list)
                        return {'ip': dic_device['ip'], 'output': command_result, 'hostname': find_hostname, 'device_type': dic_device['device_type']}
                    except:
                        return {'ip': dic_device['ip'], 'output': None, 'device_type': dic_device['device_type']}
                elif dic_device['device_type'] == 'cisco_xr':
                    try:
                        find_hostname, command_result = netmiko_send_command_cisco_xr(command_list)
                        return {'ip': dic_device['ip'], 'output': command_result, 'hostname': find_hostname, 'device_type': dic_device['device_type']}
                    except:
                        return ({'ip': dic_device['ip'], 'output': None, 'device_type': dic_device['device_type']})
                else:
                    try:
                        find_hostname, command_result = netmiko_send_command_cisco_common(command_list)
                        return {'ip': dic_device['ip'], 'output': command_result, 'hostname': find_hostname, 'device_type': dic_device['device_type']}
                    except:
                        return {'ip': dic_device['ip'], 'output': None, 'device_type': dic_device['device_type']}
            else:
                print(f"NETMIKO OR PARAMIKO FAILED TO DETERMINE DEVICE TYPE FOR DEVICE {dic_device['ip']}".center(200, '!'))

    def send_commands_threads(command_for_device, list_dic_devices, limit=limit):

        list_results_all_connections = []
        with ThreadPoolExecutor(max_workers=limit) as executor:
            futures_result = [executor.submit(send_commands, command_for_device, device) for device in list_dic_devices]
            for f in as_completed(futures_result):
                list_results_all_connections.append(f.result())
        return list_results_all_connections

    command_to_send = command
    # We run connection in parallel threads
    devices_with_output = []
    result = send_commands_threads(command_to_send, list_dic_devices, limit=limit)
    if result:
        for item in result:
            if item:
                if 'output' in item:
                    if item['output']:
                        devices_with_output.append(item)
    return True, devices_with_output


# Parsing raw data from cli output
def parse_output_textfsm(list_of_command_output, dic_index):
    # Creating list of dictionaries with data about devices
    list_all_devices_dicts = []

    for device in list_of_command_output:

        list_parsed_otput_current_device = []
        parse_check_list = [f"{device['ip']} [{device['device_type']}]".center(200, '=')]

        try:
            # We are setting compliance of device type -> command -> template
            device_type = device['device_type']
            # If we don't have output for the device we must to break iteration

            if device['output'] is None:
                print('\n', '=' * 200)
                print('\n', str('SOMETHING WENT WRONG, THERE IS NO OUTPUT FOR DEVICE ' + device['ip']).center(200, '-'))
                continue
            if device['output']:
                parse_check_list.append(f'{device["ip"]}: Output +')
            list_outpud_commands = list(device['output'].keys())
            for output_cmd in list_outpud_commands:
                def template_parse():
                    template = dic_index[device_type][output_cmd]
                    line_outpud = device['output'][output_cmd]
                    # We are opening the template file and parse the output.
                    try:
                        with open(template, 'r') as f_template:
                            re_table = textfsm.TextFSM(f_template)
                            header = re_table.header
                            result = re_table.ParseText(line_outpud)
                            device_parsed_output = [header] + result
                        parse_check_list.append(f'{device["ip"]}: Template {template} +')
                    except(FileNotFoundError):
                        print('\n', str(f'SOMETHING WENT WRONG PARSING "{output_cmd}" FOR DEVICE {device["ip"]}').center(200, '!'))
                        device_parsed_output = None
                    # Saving raw parsed output to file just in case
                    try:
                        with open('Devices_Files/' + device['hostname'] + '.txt', 'a') as raw_parsed_output:
                            raw_parsed_output.writelines('\n')
                            raw_parsed_output.writelines(str(f'Parsed output of command: "{output_cmd}" for device "{device["ip"]}"').center(200, '-'))
                            raw_parsed_output.writelines('\n')
                            raw_parsed_output.writelines(tabulate(device_parsed_output, headers='firstrow', tablefmt='grid'))
                            raw_parsed_output.writelines('\n')
                    except:
                        print('FAILED TO CREATE A TEXT FILE. DOES THE DIRECTORY "Devices_Files" EXIST IN THE SCRIPT FOLDER?'.center(200, '!'))
                    return device_parsed_output

                device_parsed_output = template_parse()

                # Collecting parsed data to new dictionary. Commands level
                list_parsed_otput_current_cmd = [dict(zip(device_parsed_output[0], x)) for x in device_parsed_output[1:]]
                # pprint(list_parsed_otput_current_cmd)
                list_parsed_otput_current_device.append(list_parsed_otput_current_cmd)
            # pprint(list_parsed_otput_current_device)
            # Gathering info about device interfaces  
            def interface_parse():
                shortcuts = {'Gi': 'GigabitEthernet', 'gi': 'GigabitEthernet', 'Fa': 'FastEthernet', 'Twe': 'TwentyFiveGigE', 'Tw': 'TwoGigabitEthernet', 'Te': 'TenGigabitEthernet', 'Po': 'Port-channel', 'po': 'Port-channel',
                             'port-channel': 'Port-channel', 'Fo': 'FortyGigabitEthernet', 'Eth': 'Ethernet', 'Ap': 'AppGigabitEthernet'}
                if device['device_type'] != 'cisco_xr' and device['device_type'] != 'cisco_wlc_ssh':
                    # Parsing "show interfaces" command in order to get data about VLANs
                    def interface_vlan_parse():
                        try:
                            vlan_info = list_parsed_otput_current_device[2]
                            if device['device_type'] == 'cisco_s200':
                                vlan_info = list_parsed_otput_current_device[1]
                            for i in vlan_info:
                                # Sorting Vlans on Each Interface
                                if i['TRUNKING_VLANS'] == ['1-4094']:
                                    i['TRUNKING_VLANS'] = ['ALL']
                                else:
                                    vlans = str(i['TRUNKING_VLANS']).strip("[]'").replace("', '", '').split(',')
                                    for z in range(len(vlans)):
                                        if '-' in vlans[z]:
                                            vlan_scope = re.compile('(\w+)-(\w+)')
                                            scope = range(int(vlan_scope.search(vlans[z]).group(1)), int(vlan_scope.search(vlans[z]).group(2)) + 1)
                                            vlans[z] = str([*scope]).strip('[]').replace(' ', '')
                                    vlans = str(vlans).strip("[]'").replace("'", '').replace(' ', '').split(',')
                                    i['TRUNKING_VLANS'] = vlans
                                    # The command "show int switchport" doesnt show up the whole name of an interface, so we must replace it
                                    for key, value in shortcuts.items():
                                        if key != re.search('([A-zZ-a]+)\d', i['INTF']).group(1):
                                            continue
                                        elif key == re.search('([A-zZ-a]+)\d', i['INTF']).group(1):
                                            i['INTF'] = i['INTF'].replace(key, value)
                                            break
                        except:
                            print('SOMETHING WENT WRONG PARSING VLANS FROM INTERFACES DATA'.center(200, '!'))
                    interface_vlan_parse()
                    if device['device_type'] == 'cisco_s200':
                        reshaped_interfaces_dictionary_list = [{x["INTF"]: x for x in y} for y in list_parsed_otput_current_device[0:2]]
                        for i in reshaped_interfaces_dictionary_list:
                            i['mgmt'] = {'INTF': 'mgmt',
                                         "PROTOCOL_STATUS": "up",
                                         'DESCRIPTION': 'Management Vlan',
                                         'PRIMARY_IP_ADDRESS': [list_parsed_otput_current_device[5][0]['IP']],
                                         'PRIMARY_IP_MASK': [list_parsed_otput_current_device[5][0]['MASK']]}
                    else:
                        reshaped_interfaces_dictionary_list = [{x["INTF"]: x for x in y} for y in list_parsed_otput_current_device[0:4]]

                elif device['device_type'] == 'cisco_xr':
                    reshaped_interfaces_dictionary_list = [{x["INTF"]: x for x in y} for y in list_parsed_otput_current_device[0:2]]
                elif device['device_type'] == 'cisco_wlc_ssh':
                    reshaped_interfaces_dictionary_list = [{x["INTF"]: x for x in y} for y in list_parsed_otput_current_device[0:2]]
                    for i in list_parsed_otput_current_device[1]:
                        try:
                            wlc_port = re.search('(\d)', i['INTF']).group(1)
                        except:
                            wlc_port = None
                        if 'PROTOCOL_STATUS' in i.keys():
                            if wlc_port:
                                i['INTF'] = 'GigabitEthernet0/0/' + wlc_port
                                i['HARDWARE_TYPE'] = 'Gigabit Ethernet'
                            if 'RP' in i['INTF'] or 'SP' in i['INTF']:
                                i['HARDWARE_TYPE'] = 'Gigabit Ethernet'
                # Merging all dictionaries by key that contains the name of the interface
                results = collections.defaultdict(dict)
                if reshaped_interfaces_dictionary_list:
                    for c in reshaped_interfaces_dictionary_list:
                        for key, value in c.items():
                            results[key] = {**results[key], **value}
                    interfaces_final_list_of_dicts = list(results.values())
                    parse_check_list.append(f'{device["ip"]}: Interfaces +')
                    return interfaces_final_list_of_dicts
                else:
                    print('SOMETHING WENT WRONG MERGING INTERFACE DATA'.center(200, '!'))
            interfaces_final_list_of_dicts = interface_parse()
            # Now We got a list where each interface is a dict with keys
            #
            # Info specific to an Enterprise
            switches = config['switches']
            switches_L3 = config['switches_L3']
            sites = config['sites']

            def software_and_manufacturer_parse():
                sotware_types = {'cisco_ios': 'Cisco IOS Software', 'cisco_nxos': 'Cisco Nexus Operating System (NX-OS) Software', 'cisco_xr': 'Cisco IOS XR Software', 'cisco_s200': 'Cisco Sx220 Series Switch Software'}
                software = None
                manufacturer = None
                if device['device_type'] == 'cisco_wlc_ssh':
                    software = list_parsed_otput_current_device[2][0]['DESCR']
                else:
                    for key, value in sotware_types.items():
                        if device['device_type'] == key:
                            software = value
                            manufacturer = re.search('^(\S+)', value).group(1)
                return software, manufacturer
            software, manufacturer = software_and_manufacturer_parse()

            def inventory_parse():
                try:
                    inventory_list = []
                    num = None
                    transivers_interfaces = []
                    if device['device_type'] == 'cisco_wlc_ssh':
                        num = 2
                    elif device['device_type'] == 'cisco_ios':
                        num = 4
                    elif device['device_type'] == 'cisco_nxos':
                        if list_parsed_otput_current_device[4]:
                            num = 4
                        elif not list_parsed_otput_current_device[4] and list_parsed_otput_current_device[9]:
                            num = 9
                    elif device['device_type'] == 'cisco_xr':
                        num = 2
                        transivers_interfaces = list_parsed_otput_current_device[5]
                    if list_parsed_otput_current_device[num]:
                        inventory_data = list_parsed_otput_current_device[num] + transivers_interfaces
                        for inv in inventory_data:
                            if 'NAME' not in inv:
                                inv['NAME'] = inv['PID']
                            if 'DESCR' not in inv:
                                inv['DESCR'] = inv['PID']
                            inventory = {'NAME': inv['NAME'].strip(),
                                         'MANUFACTURER': 'Cisco',
                                         'PID': inv['PID'].strip(),
                                         'SN': inv['SN'].strip(),
                                         'DESCRIPTION': inv['DESCR'].strip()}
                            inventory_list.append(inventory)
                        parse_check_list.append(f'{device["ip"]}: Inventory +')
                    if device['device_type'] == 'cisco_xr':
                        for inventory_module in inventory_list:
                            if 'Chassis' in inventory_module['DESCRIPTION']:
                                dev_type = inventory_module['PID']
                                serial_number = inventory_module['SN']
                    else:
                        dev_type = list_parsed_otput_current_device[num][0]['PID']
                        serial_number = list_parsed_otput_current_device[num][0]['SN']
                    return dev_type, serial_number, inventory_list
                except:
                    print('SOMETHING WENT WRONG PARSING INVENTORY DATA'.center(200, '!'))
            if device['device_type'] != 'cisco_s200':
                dev_type, serial_number, inventory_list = inventory_parse()

            def device_role_parse():
                device_role = 'router'
                # By default each device is considered a router type
                # For small business switches
                if device['device_type'] == 'cisco_s200':
                    device_role = 'switch_smb'
                # For wireless controllers
                elif device['device_type'] == 'cisco_wlc_ssh':
                    device_role = 'wlc'
                if device['device_type'] != ('cisco_wlc_ssh' and 'cisco_s200'):
                    for name in switches:
                        if name not in dev_type:
                            continue
                        elif name in dev_type:
                            device_role = 'switch'
                            break
                    for name in switches_L3:
                        if name not in dev_type:
                            continue
                        elif name in dev_type:
                            device_role = 'switch_layer_3'
                            break
                return device_role
            device_role = device_role_parse()

            def site_parse():
                site = None
                region = None
                for site_name, region in sites.items():
                    if site_name in device['hostname']:
                        site = site_name
                        region = region
                        break
                    else:
                        site = None
                        region = None
                return site, region
            site, region = site_parse()

            def vlans_parse():
                vlan_group = ''
                vlan_group_description = ''
                # Gathering Information About Vlans
                try:
                    intf_reshaped = {}
                    for o in list_parsed_otput_current_device[0]:
                        if 'lan' in o['INTF']:
                            intf_reshaped[re.search('(\d+)', o['INTF']).group(1)] = o
                    if device['device_type'] == 'cisco_ios' or device['device_type'] == 'cisco_nxos':
                        if list_parsed_otput_current_device[7] != [] and list_parsed_otput_current_device[8] == []:
                            vlan_reshaped = {i['VLAN_ID']: i for i in list_parsed_otput_current_device[7]}
                        elif list_parsed_otput_current_device[8] != [] and list_parsed_otput_current_device[7] == []:
                            vlan_reshaped = {i['VLAN_ID']: i for i in list_parsed_otput_current_device[8]}
                        elif list_parsed_otput_current_device[8] == [] and list_parsed_otput_current_device[7] == []:
                            vlan_reshaped = {}
                    elif device['device_type'] == 'cisco_s200':
                        if list_parsed_otput_current_device[4]:
                            vlan_reshaped = {i['VLAN_ID']: i for i in list_parsed_otput_current_device[4]}
                        elif not list_parsed_otput_current_device[4]:
                            vlan_reshaped = {}
                    li = [intf_reshaped, vlan_reshaped]

                    vlan = collections.defaultdict(dict)
                    for z in li:
                        for key, value in z.items():
                            vlan[key] = {**vlan[key], **value}
                    vlans_list = []
                    # prefix = str(ipaddress.ip_network(ip.address, False))
                    for i in list(vlan.values()):
                        if 'VRF' in i.keys() and i['VRF'] != '':
                            vrf = i['VRF']
                        else:
                            vrf = ''
                        if 'PRIMARY_IP_ADDRESS' in i.keys() and i['PRIMARY_IP_ADDRESS'] != []:
                            primary_prefixes = [str(ipaddress.ip_network(address, False)) for address in ['/'.join(pair) for pair in zip(i['PRIMARY_IP_ADDRESS'], i['PRIMARY_IP_MASK'])]]
                        else:
                            primary_prefixes = []
                        if 'SECONDARY_IP_ADDRESS' in i.keys() and i['SECONDARY_IP_ADDRESS'] != []:
                            secondary_prefixes = [str(ipaddress.ip_network(address, False)) for address in ['/'.join(pair) for pair in zip(i['SECONDARY_IP_ADDRESS'], i['SECONDARY_IP_MASK'])]]
                        else:
                            secondary_prefixes = []
                        if 'VLAN_ID' in i:
                            if i['INTERFACES'] == '---':
                                i['INTERFACES'] = ''
                            vlans = {'vlan_id': i['VLAN_ID'],
                                     'vlan_name': i['NAME'].rstrip(),
                                     'vlan_status': 'active',
                                     'vlan_group': vlan_group,
                                     'vlan_group_description': vlan_group_description,
                                     'vlan_ports': i['INTERFACES'],
                                     'vlan_primary_prefixes': primary_prefixes,
                                     'vlan_secondary_prefixes': secondary_prefixes,
                                     'vrf': vrf,
                                     'site': site}
                            vlans_list.append(vlans)
                    if vlans_list:
                        parse_check_list.append(f'{device["ip"]}: Vlans +')
                        return vlans_list
                except:
                    print('SOMETHING WENT WRONG PARSING VLANS DATA'.center(200, '!'))

            if device['device_type'] != 'cisco_xr' and device['device_type'] != 'cisco_wlc_ssh':
                vlans_list = vlans_parse()

            def cdp_neighbor_parse():
                try:
                    if device['device_type'] == 'cisco_s200':
                        shortcuts_cdp = {'Gi ': 'GigabitEthernet', 'gi': 'GigabitEthernet', 'Fa ': 'FastEthernet', 'Two ': 'TwoGigabitEthernet', 'Ten ': 'TenGigabitEthernet', 'Eth ': 'Ethernet'}
                    elif device['device_type'] == 'cisco_ios':
                        shortcuts_cdp = {'Gig': 'GigabitEthernet', 'gi': 'GigabitEthernet', 'Fas': 'FastEthernet', 'Two': 'TwoGigabitEthernet', 'Ten': 'TenGigabitEthernet', 'Eth': 'Ethernet', 'App': ' AppGigabitEthernet'}
                    elif device['device_type'] == 'cisco_nxos':
                        shortcuts_cdp = {'Gig': 'GigabitEthernet', 'gi': 'GigabitEthernet', 'Fas': 'FastEthernet', 'Two': 'TwoGigabitEthernet', 'Ten': 'TenGigabitEthernet', 'Eth': 'Ethernet', 'App': ' AppGigabitEthernet'}
                    elif device['device_type'] == 'cisco_xr':
                        shortcuts_cdp = {'Gi': 'GigabitEthernet', 'gi': 'GigabitEthernet', 'Fa': 'FastEthernet', 'Tw': 'TwoGigabitEthernet', 'Te': 'TenGigE', 'Et': 'Ethernet', 'Mg': 'MgmtEth'}
                    elif device['device_type'] == 'cisco_wlc_ssh':
                        shortcuts_cdp = {'Gig': 'GigabitEthernet', 'gi': 'GigabitEthernet', 'Fas': 'FastEthernet', 'Two': 'TwoGigabitEthernet', 'Ten': 'TenGigabitEthernet', 'Eth': 'Ethernet', 'App': ' AppGigabitEthernet'}
                    neighbors_list = []
                    if device['device_type'] == 'cisco_xr':
                        lso = list_parsed_otput_current_device[4]
                        for neighbor in lso:
                            for key, value in shortcuts_cdp.items():
                                if key == re.search('([A-zZ-a]+)\s*\d', neighbor['LOCAL_PORT']).group(1):
                                    neighbor['LOCAL_PORT'] = neighbor['LOCAL_PORT'].replace(key, value).replace(' ', '')
                                if key == re.search('([A-zZ-a]+)\s*\d', neighbor['REMOTE_PORT']).group(1):
                                    neighbor['REMOTE_PORT'] = neighbor['REMOTE_PORT'].replace(key, value).replace(' ', '')
                            # To get rid of domain suffix of neighbor device or nexus module suffix
                            try:
                                nexus_extras = re.search('\S+(\(\S+\))', neighbor['DEST_HOST']).group(1)
                            except:
                                nexus_extras = 'null'
                            domains = config['domains'] + [nexus_extras]
                            for domain in domains:
                                if domain not in neighbor['DEST_HOST']:
                                    continue
                                else:
                                    neighbor['DEST_HOST'] = neighbor['DEST_HOST'].replace(domain, '')
                            connection = {'DEVICE_B': neighbor['DEST_HOST'],
                                          'DEVICE_A': device['hostname'],
                                          'INTERFACE_A': neighbor['LOCAL_PORT'],
                                          'INTERFACE_B': neighbor['REMOTE_PORT']}
                            neighbors_list.append(connection)
                        parse_check_list.append(f'{device["ip"]}: Neighbors +')
                            #
                    else:
                        if device['device_type'] == 'cisco_s200':
                            lso = list_parsed_otput_current_device[3]
                        elif device['device_type'] == 'cisco_wlc_ssh':
                            lso = list_parsed_otput_current_device[3]
                        else:
                            lso = list_parsed_otput_current_device[6]
                        for neighbor in lso:
                            for key, value in shortcuts_cdp.items():
                                if key == re.search('([A-zZ-a]+)\s*\d', neighbor['LOCAL_INTERFACE']).group(1):
                                    neighbor['LOCAL_INTERFACE'] = neighbor['LOCAL_INTERFACE'].replace(key, value).replace(' ', '')
                                if key == re.search('([A-zZ-a]+)\s*\d', neighbor['NEIGHBOR_INTERFACE']).group(1):
                                    neighbor['NEIGHBOR_INTERFACE'] = neighbor['NEIGHBOR_INTERFACE'].replace(key, value).replace(' ', '')
                            try:
                                nexus_extras = re.search('\S+(\(\S+\))', neighbor['NEIGHBOR']).group(1)
                            except:
                                nexus_extras = 'null'
                            domains = config['domains'] + [nexus_extras]
                            for domain in domains:
                                if domain not in neighbor['NEIGHBOR']:
                                    continue
                                else:
                                    neighbor['NEIGHBOR'] = neighbor['NEIGHBOR'].replace(domain, '')
                            connection = {'DEVICE_B': neighbor['NEIGHBOR'],
                                          'DEVICE_A': device['hostname'],
                                          'INTERFACE_A': neighbor['LOCAL_INTERFACE'],
                                          'INTERFACE_B': neighbor['NEIGHBOR_INTERFACE']}
                            neighbors_list.append(connection)
                        parse_check_list.append(f'{device["ip"]}: Neighbors +')
                    return neighbors_list
                except:
                    print('SOMETHING WENT WRONG PARSING CDP NEIGHBORS DATA'.center(200, '!'))
            neighbors_list = cdp_neighbor_parse()

            def hsrp_parse():
                virtual_ip_list = []
                try:
                    shortcuts_hsrp = {'Vl': 'Vlan', 'Gi': 'GigabitEthernet'}
                    if list_parsed_otput_current_device[9]:
                        for virtual_interface in list_parsed_otput_current_device[9]:
                            for key, value in shortcuts_hsrp.items():
                                if key in virtual_interface['INTF']:
                                    virtual_interface['INTF'] = virtual_interface['INTF'].replace(key, value)
                            virtual_ip = {'VIRTUAL_INTERFACE': virtual_interface['INTF'],
                                          'VIRTUAL_IP': virtual_interface['VIRTUALIP'],
                                          'ACTIVE_IP': virtual_interface['ACTIVE'],
                                          'STANDBY_IP': virtual_interface['STANDBY']}
                            virtual_ip_list.append(virtual_ip)
                        parse_check_list.append(f'{device["ip"]}: hsrp +')
                        if virtual_ip_list:
                            return virtual_ip_list
                except:
                    print('SOMETHING WENT WRONG PARSING HSRP DATA'.center(200, '!'))
            if device['device_type'] == 'cisco_ios':
                virtual_ip_list = hsrp_parse()

            def cisco_wlc_parse():
                ap_list = []
                wlans = []
                try:
                    if list_parsed_otput_current_device[4] and list_parsed_otput_current_device[5]:
                        list_reshaped_aps = [{x["AP_NAME"]: x for x in y} for y in list_parsed_otput_current_device[4:6]]
                        results_ap = collections.defaultdict(dict)
                        for c in list_reshaped_aps:
                            for key, value in c.items():
                                results_ap[key] = {**results_ap[key], **value}
                        final_list_of_ap_dicts = list(results_ap.values())
                        for access_point in final_list_of_ap_dicts:
                            ap = {'AP_NAME': access_point['AP_NAME'],
                                  'AP_IP': access_point['PRIMARY_IP_ADDRESS'],
                                  'AP_MAC': access_point['MAC'],
                                  'AP_MODEL': access_point['AP_MODEL'],
                                  'AP_INTERFACE': 'GigabitEthernet0',
                                  'AP_PLATFORM': access_point['PLATFORM'],
                                  'AP_SN': access_point['SN']}
                            ap_list.append(ap)
                        parse_check_list.append(f'{device["ip"]}: Access_Points +')
                except:
                    print('SOMETHING WENT WRONG PARSING AP DATA'.center(200, '!'))
                # Getting wireless LAN list
                try:
                    if list_parsed_otput_current_device[6]:
                        for ssid in list_parsed_otput_current_device[6]:
                            wlan = {'WLANID': ssid['WLANID'],
                                    'SSID': ssid['SSID'],
                                    'INTERFACE': ssid['INTERFACE']}
                            wlans.append(wlan)
                        parse_check_list.append(f'{device["ip"]}: Wireless_LANs +')
                except:
                    print('SOMETHING WENT WRONG PARSING WLANs DATA'.center(200, '!'))
                return ap_list, wlans
            if device['device_type'] == 'cisco_wlc_ssh':
                ap_list, wlans = cisco_wlc_parse()

            # Then we create a final dict for a device
            def device_final_dict():
                if device['device_type'] == 'cisco_wlc_ssh':
                    platform = software
                    final_device_dict = {
                        'MANUFACTURER': 'Cisco',
                        'DEVICE_NAME': device['hostname'],
                        'DEVICE_IP': device['ip'],
                        'REGION': region,
                        'SITE': site,
                        'DEVICE_TYPE': list_parsed_otput_current_device[2][0]['PID'],
                        'DEVICE_PLATFORM': platform,
                        'SOFTWARE': 'Cisco Air OS',
                        'DEVICE_ROLE': device_role,
                        'SERIAL_NUMBER': list_parsed_otput_current_device[2][0]['SN'],
                        'INTERFACES': interfaces_final_list_of_dicts,
                        'AP': ap_list,
                        'CONNECTIONS': neighbors_list,
                        'WLANS': wlans,
                        'INVENTORY': inventory_list
                    }
                if device['device_type'] == 'cisco_s200':
                    final_device_dict = {
                        'MANUFACTURER': manufacturer,
                        'DEVICE_NAME': device['hostname'],
                        'DEVICE_IP': device['ip'],
                        'REGION': region,
                        'SITE': site,
                        'DEVICE_TYPE': list_parsed_otput_current_device[2][0]['PID'],
                        'DEVICE_PLATFORM': 'Sx220',
                        'SOFTWARE': software,
                        'DEVICE_ROLE': device_role,
                        'SERIAL_NUMBER': list_parsed_otput_current_device[2][0]['SN'],
                        'INTERFACES': interfaces_final_list_of_dicts,
                        'VLANS': vlans_list,
                        'CONNECTIONS': neighbors_list
                    }
                if device['device_type'] == 'cisco_ios':
                    final_device_dict = {
                        'MANUFACTURER': manufacturer,
                        'DEVICE_NAME': device['hostname'],
                        'DEVICE_IP': device['ip'],
                        'REGION': region,
                        'SITE': site,
                        'DEVICE_TYPE': list_parsed_otput_current_device[4][0]['PID'],
                        'DEVICE_PLATFORM': list_parsed_otput_current_device[5][0]['PLATFORM'],
                        'SOFTWARE': software,
                        'DEVICE_ROLE': device_role,
                        'SERIAL_NUMBER': list_parsed_otput_current_device[4][0]['SN'],
                        'INTERFACES': interfaces_final_list_of_dicts,
                        'VLANS': vlans_list,
                        'CONNECTIONS': neighbors_list,
                        'HSRP': virtual_ip_list,
                        'INVENTORY': inventory_list
                    }
                if device['device_type'] == 'cisco_xr':
                    platform = 'IOS-XR'
                    final_device_dict = {
                        'MANUFACTURER': manufacturer,
                        'DEVICE_NAME': device['hostname'],
                        'DEVICE_IP': device['ip'],
                        'REGION': region,
                        'SITE': site,
                        'DEVICE_TYPE': dev_type,
                        'DEVICE_PLATFORM': platform,
                        'SOFTWARE': software,
                        'DEVICE_ROLE': device_role,
                        'SERIAL_NUMBER': serial_number,
                        'INTERFACES': interfaces_final_list_of_dicts,
                        'CONNECTIONS': neighbors_list,
                        'INVENTORY': inventory_list
                    }
                if device['device_type'] == 'cisco_nxos':
                    platform = 'NX-OS'
                    final_device_dict = {
                        'MANUFACTURER': manufacturer,
                        'DEVICE_NAME': device['hostname'],
                        'DEVICE_IP': device['ip'],
                        'REGION': region,
                        'SITE': site,
                        'DEVICE_TYPE': dev_type,
                        'DEVICE_PLATFORM': platform,
                        'SOFTWARE': software,
                        'DEVICE_ROLE': device_role,
                        'SERIAL_NUMBER': serial_number,
                        'INTERFACES': interfaces_final_list_of_dicts,
                        'VLANS': vlans_list,
                        'CONNECTIONS': neighbors_list,
                        'INVENTORY': inventory_list
                    }
                return final_device_dict
            final_device_dict = device_final_dict()
            # Then we create a final list of dict for all devices
            list_all_devices_dicts.append(final_device_dict)
            print(*parse_check_list, sep='\n')
        except:
            print(f"PARSING DATA FROM DEVICE {device['hostname']} FAILED".center(200, '!'))
            pass

    with open('devices_api.csv', 'w', encoding='utf8') as file:
        json.dump(list_all_devices_dicts, file, indent=16, sort_keys=True)
    with open('devices_api.csv') as json_file:
        device_list = json.load(json_file)
    for device in device_list:
        name = device['DEVICE_NAME']
        with open('api//' + name + '.csv', 'w', encoding='utf8') as file:
            json.dump([device], file, indent=16, sort_keys=True)
    return True, list_all_devices_dicts


# Flag of the correct execution of each step of the script
all_doing_well = False
# Timer of showing error notification
sleep_time = 5
# Choosing a File
if file_with_ip_addresses == 'all':
    with open('ip_list_all.txt', 'r') as f:
        request_ip_address_list = re.findall('\d+\.\d+\.\d+\.\d+', f.read())
elif file_with_ip_addresses == 'confluence':
    request_ip_address_list = confluence()
elif file_with_ip_addresses == 'test':
    with open('ip_list.txt', 'r') as f:
        request_ip_address_list = re.findall('\d+\.\d+\.\d+\.\d+', f.read())
list_reachable_ips = None
list_unreachable_ips = None
if request_ip_address_list:
    all_doing_well, list_reachable_ips, list_unreachable_ips = connect_list(request_ip_address_list)
else:
    print('\n', '=' * 200)
    print(str('NO IPs in a FILE. CHECK IT OUT').center(200, ' '))
    print('=' * 200)
    time.sleep(sleep_time)
    exit()
if list_reachable_ips:
    all_doing_well, list_of_dic_devices = device_dictionary(list_reachable_ips)
else:
    print('\n', '=' * 200)
    print(str('IP LIST IS EMPTY OR SOMETHING WENT WRONG MAKING LIST OF DICTS').center(200, ' '))
    print('=' * 200)
    time.sleep(sleep_time)
    if list_unreachable_ips:
        print('\n')
        print(str('SSH PORT IS CLOSED ON THESE DEVICES').center(200, ' '))
        for i in list_unreachable_ips:
            print(str(i).center(200, '-'))
    exit()
if all_doing_well:
    # The commands are little different for different devices types
    dic_command = {'cisco_ios': ['show ip interface',
                                 'show interfaces',
                                 'show interfaces switchport',
                                 'show running-config',
                                 'show inventory',
                                 'show version',
                                 'show cdp neighbors',
                                 'show vlan',
                                 'show vlan-switch',
                                 'show standby brief'],
                   'cisco_xr': ['show ipv4 interface',
                                'show interfaces',
                                'show inventory all',
                                'show version',
                                'show cdp neighbors detail'],
                   'cisco_nxos': ['show ip interface vrf all',
                                  'show interface',
                                  'show interface switchport',
                                  'show running-config',
                                  'show inventory all',
                                  'show version',
                                  'show cdp neighbors',
                                  'show vlan',
                                  'show vlan-switch',
                                  'show inventory'],
                   'cisco_s200': ['show interfaces GigabitEthernet 1-50',
                                  'show running-config',
                                  'show version',
                                  'show cdp neighbor',
                                  'show vlan',
                                  'show ip'],
                   'cisco_wlc_ssh': ['show port summary',
                                     'show inventory',
                                     'show cdp neighbors',
                                     'show ap summary',
                                     'show ap inventory all',
                                     'show wlan summary']}

    all_doing_well, list_command_output = send_command_and_get_output(list_of_dic_devices, dic_command, limit=limit)
# Parsing output of devices by TextFSM
if all_doing_well:
    # We use different template for parsing of different output of different type of device
    dic_parse_index = {'cisco_ios': {'show ip interface': 'templates/cisco_ios_show_ip_interface.template',
                                     'show interfaces': 'templates/cisco_ios_show_interfaces.template',
                                     'show interfaces switchport': 'templates/cisco_ios_show_interfaces_switchport.template',
                                     'show running-config': 'templates/cisco_ios_show_running_config.template',
                                     'show inventory': 'templates/cisco_ios_show_inventory.template',
                                     'show version': 'templates/cisco_ios_show_version.template',
                                     'show cdp neighbors': 'templates/cisco_ios_show_cdp_neighbors.template',
                                     'show vlan': 'templates/cisco_ios_show_vlan.template',
                                     'show vlan-switch': 'templates/cisco_ios_show_vlan.template',
                                     'show standby brief': 'templates/cisco_ios_show_standby_brief.template'},
                       'cisco_xr': {'show ipv4 interface': 'templates/cisco_xr_show_ipv4_interface.template',
                                    'show interfaces': 'templates/cisco_xr_show_interfaces.template',
                                    'show inventory all': 'templates/cisco_xr_show_inventory_all.template',
                                    'show version': 'templates/cisco_xr_show_version.template',
                                    'show cdp neighbors detail': 'templates/cisco_xr_show_cdp_neighbors_detail.template',
                                    'show controllers interface': 'templates/cisco_xr_show_controllers_interface.template'},
                       'cisco_nxos': {'show ip interface vrf all': 'templates/cisco_nxos_show_ip_interface_vrf_all.template',
                                      'show interface': 'templates/cisco_nxos_show_interface.template',
                                      'show interface switchport': 'templates/cisco_nxos_show_interface_switchport.template',
                                      'show running-config': 'templates/cisco_nxos_show_running_config.template',
                                      'show inventory all': 'templates/cisco_nxos_show_inventory_all.template',
                                      'show version': 'templates/cisco_nxos_show_version.template',
                                      'show cdp neighbors': 'templates/cisco_nxos_show_cdp_neighbors.template',
                                      'show vlan': 'templates/cisco_nxos_show_vlan.template',
                                      'show vlan-switch': 'templates/cisco_nxos_show_vlan.template',
                                      'show inventory': 'templates/cisco_nxos_show_inventory.template'},
                       'cisco_s200': {'show interfaces GigabitEthernet 1-50': 'templates/cisco_s200_show_gigabit_interface.template',
                                      'show running-config': 'templates/cisco_s200_show_running_config.template',
                                      'show version': 'templates/cisco_s200_show_version.template',
                                      'show cdp neighbor': 'templates/cisco_s200_show_cdp_neighbor.template',
                                      'show vlan': 'templates/cisco_s200_show_vlan.template',
                                      'show ip': 'templates/cisco_s200_show_ip.template'},
                       'cisco_s350': {'show interfaces switchport': 'templates/cisco_s350_show_interfaces_switchport.template',
                                      'show running-config': 'templates/cisco_s350_show_running_config.template',
                                      'show inventory': 'templates/cisco_s350_show_inventory.template',
                                      'show cdp neighbor': 'templates/cisco_s350_show_cdp_neighbor.template',
                                      'show vlan': 'templates/cisco_s350_show_vlan.template',
                                      'show ip interface': 'templates/cisco_s350_show_ip_interface.template'},
                       'cisco_wlc_ssh': {'show interface detailed': 'templates/cisco_wlc_ssh_show_interface_detailed.template',
                                         'show port summary': 'templates/cisco_wlc_ssh_show_port_summary.template',
                                         'show inventory': 'templates/cisco_wlc_ssh_show_inventory.template',
                                         'show cdp neighbors': 'templates/cisco_wlc_ssh_show_cdp_neighbors.template',
                                         'show ap summary': 'templates/cisco_wlc_ssh_show_ap_summary.template',
                                         'show ap inventory all': 'templates/cisco_wlc_ssh_show_ap_inventory_all.template',
                                         'show wlan summary': 'templates/cisco_wlc_ssh_show_wlan_summary.template'}
                       }

    all_doing_well, parsed_devices_output = parse_output_textfsm(list_command_output, dic_parse_index)
print('\n', '=' * 200, '\n')
if unable_to_login_by_ssh_ip_list:
    print(str('UNABLE TO LOGIN BY SSH ON THESE DEVICES').center(200, ' '))
    for i in unable_to_login_by_ssh_ip_list:
        print(str(i).center(200, '-'))
    print('+++++++++++++'.center(200))
if list_unreachable_ips:
    print(str('SSH PORT IS CLOSED ON THESE DEVICES').center(200, ' '))
    for i in list_unreachable_ips:
        print(str(i).center(200, '-'))
if authentication_failed_list:
    print(str('AUTHENTICATION FAILED ON THESE DEVICES').center(200, ' '))
    for i in authentication_failed_list:
        print(str(i).center(200, '-'))
if not (unable_to_login_by_ssh_ip_list or list_unreachable_ips or authentication_failed_list):
    print(str('NO SSH CONNECTION OR AUTHENTICATION ERRORS').center(200, ' '))
print('\n', '=' * 200)
time.sleep(sleep_time)
exit()
