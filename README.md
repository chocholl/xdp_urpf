# xdp_urpf

## Info

Pretty fast XDP-based URPF implementation that leverages hierarchical data structures to perform high-speed packet filtering.
Two lookups are in use; the first one, keyed with the source MAC address, brings a pointer to the LPM-trie table containing ACL entries to perform a second, source IP-based lookup.

## Use cases

Being attached to the TAP interface at the hypervisor side, it efficiently enforces access control filtering, preventing VM from source spoofing.

## Compile and Attach to NIC/vNIC

```
cd repo_dir
make
bash ./attach
```

## ACL editing

ACLs are stored in text files with lines representing individual allowed source networks a given VM may use.

```
cat ./2d-8d-16-ca.acl
10.213.76.0/29
10.15.67.12/32
```

Having ACL prepared just run CLI script that updates in-kernel data-structures.
In order to add entries run the following command
```
python3 update_map.py --mac f0-1c-2d-8d-16-ca --command add --file ./2d-8d-16-ca.acl
```

In order to delete entries run the following command
```
python3 update_map.py --mac f0-1c-2d-8d-16-ca --command del
```

## Further development

* IPv6 support is the next goal to achieve.
* Preventing ARP/NDP poisoning is due.
