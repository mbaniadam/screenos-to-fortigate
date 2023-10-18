import json
import os
import sys

os.chdir(os.path.dirname(os.path.abspath(sys.argv[0])))
path = os.getcwd()
print(path)


def define_ports(ports_dic):
    for port_name, port_data in ports_dic.items():
        if len(port_data[0].split('_')) >= 5:
            port_type = port_data[0].split('_')[0]
            dst_port_range = port_data[0].split('_')[4]
            converted_config.write(f"edit {port_name}\n")
            converted_config.write(
                f"set {port_type}-portrange {dst_port_range}\n")
            converted_config.write("next\n")


def define_addr(address_data):

    for address_name, address_value in address_data.items():
        if isinstance(address_value, list):
            # If the value is a list, assume it's a subnet and add it to the addresses
            subnet = ''.join(address_data.get(address_name))
            converted_config.write(f"edit {address_name}\n")
            converted_config.write(f"set subnet {subnet}\n")
            converted_config.write("next\n")
        elif isinstance(address_value, dict):
            # If the value is a dictionary, recursively extract addresses from it
            grp_name = address_name
            grp_memebers = address_value
            groups.update({grp_name: grp_memebers})


def define_addrgrp(grp_memebers):
    for grp_name, member in grp_memebers.items():
        members = ' '.join(f'"{w}"' for w in member.keys())
        converted_config.write(f"edit {grp_name}\n")
        converted_config.write(f"append member {members}\n")
        converted_config.write("next\n")



def policy_writer(policy_id, policy_name, src_int, dst_int, src_addr, dst_addr, port, action, scheduler, count):
    converted_config.write(f"edit {policy_id}\n")
    converted_config.write(f"set name \"{policy_name}-P{policy_id}\"\n")
    converted_config.write(f"set srcintf {src_int}\n")
    converted_config.write(f"set dstintf {dst_int}\n")
    converted_config.write(f"set srcaddr {src_addr}\n")
    converted_config.write(f"set dstaddr {dst_addr}\n")
    # list(filter(lambda item: converted_config.write(f"set srcaddr {item}\n"), source_addr))
    # list(filter(lambda item: converted_config.write(f"set dstaddr {item}\n"), dst_addr))
    converted_config.write(f"set action {action}\n")
    if scheduler:
        converted_config.write(f"set schedule {scheduler}\n")
    else:
        converted_config.write("set schedule always\n")
        pass
    converted_config.write(f"set service {port}\n")
    # list(filter(lambda item: converted_config.write(f"set service {item}\n"), port))
    # converted_config.write(f"set service {port}\n")
    if action == "accept":
        converted_config.write(
            f"set utm-status enable\nset ssl-ssh-profile 'certificate-inspection'\nset ips-sensor 'Def_High'\nset logtraffic all\nnext\n")
    else:
        converted_config.write(f"set logtraffic all\nnext\n")
    count += 1


with open("parsed_config.json") as backup_file,\
        open("converted_config.txt", "w") as converted_config:
    data = json.load(backup_file)
    count = 0
    groups = {}
    ports_dic = {}
    converted_config.write("config firewall address\n")
    for pol_id, policy in data.items():
        p_srcaddr = policy["src_addr"]
        define_addr(p_srcaddr)
        p_dstaddr = policy["dst_addr"]
        define_addr(p_dstaddr)
    converted_config.write("end\n")
    converted_config.write("config firewall addrgrp\n")
    for pol_id, policy in data.items():
        define_addrgrp(groups)
    converted_config.write("end\n")
    converted_config.write("config firewall services custom\n")
    for pol_id, policy in data.items():
        ports_dic.update(policy["pol_proto"])
    define_ports(ports_dic)
    converted_config.write("end\n")
    converted_config.write("config firewall policy\n")
    for pol_id, policy in data.items():
        p_name = policy["pol_name"]
        p_srcint = policy["src_zone"]
        p_dstint = policy["dst_zone"]#f'"{w}"' for w in
        p_srcaddr = ' '.join(list(map(lambda x: f'"{x}"', policy["src_addr"].keys())))
        p_dstaddr = ' '.join(list(map(lambda x: f'"{x}"', policy["dst_addr"].keys())))
        p_ports = ' '.join(list(map(lambda x: f'"{x}"', policy["pol_proto"].keys())))
        p_action = policy["pol_action"]
        p_log = policy["log_action"]
        p_scheduler = "always"
        if p_srcaddr == '"Any"':
            p_srcaddr = "all"
        if p_dstaddr == '"Any"':
            p_dstaddr = "all"
        if p_ports == '"ANY"':
            p_ports = "ALL"
        if p_srcaddr == "all" and p_dstaddr == "all" and p_ports == "ALL":
            print(f"Policy {pol_id} with source {p_srcaddr} and destination {p_dstaddr} founded.\n\
                  It might be dangerous. Ignored!")
        else:
            policy_writer(pol_id, p_name, p_srcint, p_dstint, p_srcaddr,
                          p_dstaddr, p_ports, p_action, p_scheduler, count)
