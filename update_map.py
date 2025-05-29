import subprocess
import ast
import argparse
import ipaddress

MAP_PREFIX = ''

def f_ip(n_addr):
    return f'{hex(int(n_addr.split(".")[0]))} {hex(int(n_addr.split(".")[1]))} {hex(int(n_addr.split(".")[2]))} {hex(int(n_addr.split(".")[3]))}'

def f_mac(n_mac):
    return f'{n_mac.split("-")[-4]} {n_mac.split("-")[-3]} {n_mac.split("-")[-2]} {n_mac.split("-")[-1]}'

parser = argparse.ArgumentParser()
parser.add_argument('--mac', help='mac address in HEX format xx-xx-xx-xx-xx-xx', required=True)
parser.add_argument('--file', help='access control entries file name')
parser.add_argument('--command', help='add/delete action to take', required=True)
args = parser.parse_args()

table_name = args.mac.replace('-', '')

if args.command == 'del':
    cli_command = f'bpftool map delete name outer_hash key hex {f_mac(args.mac)}'
    subprocess.check_output(cli_command, shell=True, text=True)

    cli_command = f'rm /sys/fs/bpf/{MAP_PREFIX}_{table_name}'
    subprocess.check_output(cli_command, shell=True, text=True)

if args.command == 'add':
    cli_command = f'bpftool map create /sys/fs/bpf/{MAP_PREFIX}_{table_name} type lpm_trie key 8 value 1 entries 20 flags 1 name {MAP_PREFIX}_{table_name}'
    subprocess.check_output(cli_command, shell=True, text=True)

    cli_command = f'bpftool -j map show name {MAP_PREFIX}_{table_name}'
    system_output = subprocess.check_output(cli_command, shell=True, text=True)
    inner_map = ast.literal_eval(system_output)

    with open(args.file, 'r') as file:
        for line in file:
            ip_network = ipaddress.ip_network(line.strip())
            n_addr = str(ip_network.network_address)
            p_len = ip_network.prefixlen
            cli_command = f'bpftool map update id {inner_map["id"]} key hex {hex(p_len)} 00 00 00 {f_ip(n_addr)} value hex 01'
            subprocess.check_output(cli_command, shell=True, text=True)

    cli_command = f'bpftool map update pinned /sys/fs/bpf/outer_hash key hex {f_mac(args.mac)} value id {inner_map["id"]}'
    subprocess.check_output(cli_command, shell=True, text=True)
