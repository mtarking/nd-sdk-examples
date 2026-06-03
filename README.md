# ND SDK Example

CLI tool to manage iBGP VXLAN EVPN fabric lifecycle on Nexus Dashboard using the `cisco.nd-infra` and `cisco.nd-manage` Python SDK packages.

Reads all configuration from a YAML data model file.

## Operations

| Operation | Description |
|-----------|-------------|
| `fabric` | Create the VXLAN EVPN fabric |
| `inventory` | Onboard switches into the fabric |
| `vrfs` | Create VRFs in the fabric |
| `networks` | Create L2/L3 networks in the fabric |
| `interfaces` | Configure switch interfaces |
| `attach_vrfs` | Attach VRFs to switches |
| `attach_nets` | Attach networks to switches (with port assignments) |
| `deploy` | Deploy pending VRF and network configs to switches |
| `reconcile` | Remove stale VRFs/networks not in YAML from controller |
| `all` | Run all operations in sequence (excludes reconcile) |

## Usage

```bash
python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password <PASSWORD> --operation <OP>
```

## Examples

### Create fabric only

```bash
python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation fabric
```

### Onboard switches

```bash
python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation inventory
```

### Create VRFs and networks

```bash
python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation vrfs
python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation networks
```

### Attach VRFs and networks to switches

```bash
python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation attach_vrfs
python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation attach_nets
```

### Deploy VRF and network configs to switches

```bash
python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation deploy
```

### Configure interfaces

```bash
python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation interfaces
```

### Reconcile (remove stale VRFs/networks from controller)

```bash
# Dry run — show what would be removed
python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation reconcile --dry-run

# Execute removal
python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation reconcile
```

### Run everything (excludes reconcile)

```bash
python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation all
```

### Using environment variable for password

```bash
export ND_PASSWORD='cisco.123'
python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --operation all
```

### Using an API key (skips login)

```bash
python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --api-key '<KEY>' --operation all
```

### API key via environment variable

```bash
export ND_API_KEY='<KEY>'
python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --operation all
```
