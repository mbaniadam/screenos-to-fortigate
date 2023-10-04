import json
import os
import sys

os.chdir(os.path.dirname(os.path.abspath(sys.argv[0])))
path = os.getcwd()
print(path)


def define_ports(port_data):
    port = ""
    if "-" in port_data:
        port_low = port_data.split("-")[1]
        try:
            # Port-23456-23457
            port_high = port_data.split("-")[2]
        except:
            port_high = port_data.split("-")[1]
        if port_low == port_high:
            port = port_low
        else:
            port = f"{port_low}-{port_high}"
        return port


def define_addr(line, description):
    address_name = line.split()[7]
    subnet = line.split()[8]
    converted_file.write(f"edit {address_name}\n")
    converted_file.write(f"set subnet {subnet}\n")
    converted_file.write(f"set comment {description}\n")
    converted_file.write("next\n")


def define_addrgrp(converted_grp):
    grp_name = line.split()[7]
    address_name = line.split()[9]
    converted_grp.write(f"edit {grp_name}\n")
    converted_grp.write(f"append member {address_name}\n")
    converted_grp.write("next\n")


def define_vlans(converted_vlans):
    vlan_id = line.split()[6]
    vlan_name = line.split()[10]
    vlan_name = ipaddress.ip_interface(vlan_name)
    vlan_name_new = vlan_name.network
    vlan_ip = line.split()[10]
    converted_vlans.write(f"edit {vlan_name_new}\n")
    converted_vlans.write("set vdom ''\n")
    converted_vlans.write(f"set ip {vlan_ip}\n")
    converted_vlans.write(
        """set allowaccess ping\nset status down\nset role dmz\nset interface 'PO-1'\n""")
    converted_vlans.write(f"set vlanid {vlan_id}\n")
    converted_vlans.write("next\n")


def policy_writer(policy_id, policy_name, src_int, dst_int, src_addr, dst_addr, port, action, scheduler, count, converted_policies):
    converted_policies.write(f"edit {policy_id}\n")
    converted_policies.write(f"set name {policy_name}-P{policy_id}\n")
    converted_policies.write(f"set srcintf {src_int}\n")
    converted_policies.write(f"set dstintf {dst_int}\n")
    converted_policies.write(f"set srcaddr {src_addr}\n")
    converted_policies.write(f"set dstaddr {dst_addr}\n")
    # list(filter(lambda item: converted_policies.write(f"set srcaddr {item}\n"), source_addr))
    # list(filter(lambda item: converted_policies.write(f"set dstaddr {item}\n"), dst_addr))
    converted_policies.write(f"set action {action}\n")
    if scheduler:
        converted_policies.write(f"set schedule {scheduler}\n")
    else:
        converted_policies.write("set schedule always\n")
        pass
    converted_policies.write(f"set service {port}\n")
    # list(filter(lambda item: converted_policies.write(f"set service {item}\n"), port))
    # converted_policies.write(f"set service {port}\n")
    if action == "accept":
        converted_policies.write(
            f"set utm-status enable\nset ssl-ssh-profile 'certificate-inspection'\nset ips-sensor 'BMC_High'\nset logtraffic all\nnext\n")
    else:
        converted_policies.write(f"set logtraffic all\nnext\n")
    count += 1


with open("fg_conf.json") as backup_file,\
        open("converted_policies.txt", "w") as converted_policies:
    data = json.load(backup_file)
    count = 0
    for pol_id, policy in data.items():
        p_name = policy["pol_name"]
        p_srcint = policy["src_zone"]
        p_srcint = policy["dst_zone"]
        p_srcaddr = ' '.join(list(map(lambda x: x, policy["src_addr"].keys())))
        p_dstaddr = ' '.join(list(map(lambda x: x, policy["dst_addr"].keys())))
        p_ports = ' '.join(list(map(lambda x: x, policy["pol_proto"].keys())))
        p_action = policy["pol_action"]
        p_log = policy["log_action"]
        p_scheduler = "always"
        policy_writer(pol_id, p_name, p_srcint, p_srcint, p_srcaddr,
                      p_dstaddr, p_ports, p_action, p_scheduler, count, converted_policies)
        # src_addr = ' '.join(addr_name for addr_name in policy["src_addr"].keys())
        # dst_addr = ' '.join(addr_name for addr_name in policy["dst_addr"].keys())
