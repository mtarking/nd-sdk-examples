#!/usr/bin/env python3
"""
CLI tool to manage iBGP VXLAN EVPN fabric lifecycle on Nexus Dashboard
using the cisco.nd-infra and cisco.nd-manage Python SDK packages.

Reads all configuration from a YAML data model file.

Operations:
    fabric      - Create the VXLAN EVPN fabric
    inventory   - Onboard switches into the fabric
    vrfs        - Create VRFs in the fabric
    networks    - Create L2/L3 networks in the fabric
    interfaces  - Configure switch interfaces
    attach_vrfs - Attach VRFs to switches
    attach_nets - Attach networks to switches (with port assignments)
    deploy      - Deploy pending VRF and network configs to switches
    reconcile   - Remove stale VRFs/networks not in YAML from controller
    all         - Run all operations in sequence (excludes reconcile)

Usage:
    python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password <PASSWORD> --operation <OP>

Examples:
    # Create fabric only
    python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation fabric

    # Onboard switches
    python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation inventory

    # Create VRFs and networks
    python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation vrfs
    python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation networks

    # Attach VRFs and networks to switches
    python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation attach_vrfs
    python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation attach_nets

    # Deploy VRF and network configs to switches
    python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation deploy

    # Configure interfaces
    python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation interfaces

    # Reconcile: remove VRFs/networks from controller that are not in YAML
    python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation reconcile --dry-run
    python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation reconcile

    # Run everything (excludes reconcile)
    python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --password 'cisco.123' --operation all

    # Using environment variable for password
    export ND_PASSWORD='cisco.123'
    python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --operation all

    # Using an API key (skips login)
    python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --api-key '<KEY>' --operation all

    # API key via environment variable
    export ND_API_KEY='<KEY>'
    python manage_vxlan_ibgp_fabric.py --data fabric_data.yaml --operation all
"""

import argparse
import os
import sys

import urllib3
import yaml

import cisco.nd_infra
from cisco.nd_infra.api import AuthenticationApi
from cisco.nd_infra.models import LoginPayload

import cisco.nd_manage
from cisco.nd_manage.api import (
    ConfigurationDeploymentApi,
    FabricManagementApi,
    InterfacesApi,
    InventoryApi,
    VRFsAndNetworksApi,
)
from cisco.nd_manage.exceptions import ApiException
from cisco.nd_manage.models import (
    AddSwitchesRequestBody,
    BaseFabric,
    CreateInterfaceRequest,
    CreateNetworksRequest,
    CreateVrfsRequest,
    DeployVrfsRequest,
    ExecuteSwitchConfigDeployRequest,
    Fabric,
    ManagementSettingsManagement,
    NetworkAttachment,
    NetworkAttachmentInterfaces,
    NetworkBase,
    NetworkSwitchesList,
    NetworAttachDetachPayload,
    SchemasAccessInterface,
    SchemasTrunkInterface,
    SchemasVxlanIbgp,
    SwitchDiscovery,
    TelemetryStreamingProtocol,
    VrfAttachment,
    VrfAttachDetachPayload,
    VrfAttachmentInstanceValues,
    VrfSchema,
    VxlanCoreData,
    VxlanIbgp,
    VxlanIbgpVrf,
)

# ──────────────────────────────────────────────────────────────────────────────
# CLI Argument Parsing
# ──────────────────────────────────────────────────────────────────────────────

OPERATIONS = ["fabric", "inventory", "vrfs", "networks", "attach_vrfs", "attach_nets", "deploy", "interfaces", "reconcile", "all"]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Manage iBGP VXLAN EVPN fabric lifecycle on Nexus Dashboard from a YAML data model"
    )
    parser.add_argument(
        "--host", default=None,
        help="Nexus Dashboard IP or hostname (overrides YAML)"
    )
    parser.add_argument(
        "--user", default=None,
        help="Username (overrides YAML)"
    )
    parser.add_argument(
        "--password", default=None,
        help="User password (overrides ND_PASSWORD env var)"
    )
    parser.add_argument(
        "--api-key", default=None,
        help="API key for authentication (overrides ND_API_KEY env var; skips login)"
    )
    parser.add_argument(
        "--data", required=True, help="Path to YAML fabric data model file"
    )
    parser.add_argument(
        "--operation", choices=OPERATIONS, default="all",
        help="Operation to perform (default: all)"
    )
    parser.add_argument(
        "--verify-ssl", action="store_true", default=None,
        help="Override SSL verification (default: from YAML)"
    )
    parser.add_argument(
        "--dry-run", action="store_true", default=False,
        help="Show what reconcile would do without making changes"
    )
    return parser.parse_args()


def load_data(path: str) -> dict:
    """Load and validate the YAML data model file."""
    with open(path, "r") as f:
        data = yaml.safe_load(f)

    if not data or "connection" not in data:
        print("ERROR: YAML must contain a 'connection' top-level key.", file=sys.stderr)
        sys.exit(1)

    return data


# ──────────────────────────────────────────────────────────────────────────────
# Authentication
# ──────────────────────────────────────────────────────────────────────────────

def login(host: str, user: str, password: str, domain: str, verify_ssl: bool) -> str:
    """Authenticate to Nexus Dashboard and return JWT token."""
    infra_config = cisco.nd_infra.Configuration(
        host=f"https://{host}/api/v1/infra"
    )
    infra_config.verify_ssl = verify_ssl

    with cisco.nd_infra.ApiClient(infra_config) as infra_client:
        auth_api = AuthenticationApi(infra_client)
        login_payload = LoginPayload(
            user_name=user,
            user_passwd=password,
            domain=domain,
        )
        response = auth_api.execute_login(login_payload=login_payload)

    token = response.jwttoken or response.token
    if not token:
        print("ERROR: Login succeeded but no token was returned.", file=sys.stderr)
        sys.exit(1)

    return token


def get_manage_client(host: str, token: str, verify_ssl: bool):
    """Create a configured nd_manage ApiClient."""
    manage_config = cisco.nd_manage.Configuration(
        host=f"https://{host}/api/v1/manage",
        access_token=token,
    )
    manage_config.verify_ssl = verify_ssl
    return cisco.nd_manage.ApiClient(manage_config)


# ──────────────────────────────────────────────────────────────────────────────
# Operation: Create Fabric
# ──────────────────────────────────────────────────────────────────────────────

def op_create_fabric(client, data: dict):
    """Create an iBGP VXLAN EVPN fabric from YAML data."""
    fabric_data = data["fabric"]
    mgmt = fabric_data["management"]

    # Pass all YAML management keys directly to VxlanIbgp.
    # Any valid VxlanIbgp field (snake_case) is a valid YAML key.
    vxlan_ibgp = VxlanIbgp(**mgmt)

    management = ManagementSettingsManagement(actual_instance=vxlan_ibgp)

    # Build Fabric kwargs including optional telemetry settings
    fabric_kwargs = dict(
        name=fabric_data["name"],
        category=fabric_data.get("category", "fabric"),
        management=management,
    )

    # Telemetry parameters (Fabric-level, not VxlanIbgp-level)
    if "telemetry_collection" in fabric_data:
        fabric_kwargs["telemetry_collection"] = fabric_data["telemetry_collection"]
    if "telemetry_collection_type" in fabric_data:
        fabric_kwargs["telemetry_collection_type"] = fabric_data["telemetry_collection_type"]
    if "telemetry_streaming_protocol" in fabric_data:
        protocol = fabric_data["telemetry_streaming_protocol"]
        fabric_kwargs["telemetry_streaming_protocol"] = TelemetryStreamingProtocol(protocol)
    if "telemetry_source_interface" in fabric_data:
        fabric_kwargs["telemetry_source_interface"] = fabric_data["telemetry_source_interface"]
    if "telemetry_source_vrf" in fabric_data:
        fabric_kwargs["telemetry_source_vrf"] = fabric_data["telemetry_source_vrf"]

    fabric = Fabric(**fabric_kwargs)
    base_fabric = BaseFabric(actual_instance=fabric)

    fabric_api = FabricManagementApi(client)
    try:
        result = fabric_api.create_fabric(base_fabric=base_fabric)
        print(f"  Fabric '{fabric_data['name']}' created successfully.")
    except ApiException as e:
        if e.status == 400 and "already present" in str(e.body):
            # Fabric exists — update it to match desired state
            result = fabric_api.updatefabric_details(
                fabric_name=fabric_data["name"],
                base_fabric=base_fabric,
            )
            print(f"  Fabric '{fabric_data['name']}' updated successfully.")
        else:
            raise
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Operation: Onboard Switches
# ──────────────────────────────────────────────────────────────────────────────

def op_onboard_switches(client, data: dict):
    """Add switches to the fabric inventory."""
    fabric_name = data["fabric"]["name"]
    inv = data["inventory"]

    switches = []
    for sw in inv["switches"]:
        switch_kwargs = dict(
            hostname=sw["hostname"],
            ip=sw["ip"],
            serial_number=sw["serial_number"],
            model=sw["model"],
        )
        if "software_version" in sw:
            switch_kwargs["software_version"] = sw["software_version"]
        if "switch_role" in sw:
            switch_kwargs["switch_role"] = sw["switch_role"]
        switches.append(SwitchDiscovery(**switch_kwargs))

    request_body = AddSwitchesRequestBody(
        switches=switches,
        username=inv.get("username"),
        password=inv.get("password"),
        platform_type=inv.get("platform_type", "nx-os"),
        preserve_config=inv.get("preserve_config", True),
    )

    inventory_api = InventoryApi(client)
    try:
        inventory_api.create_fabric_switches(
            fabric_name=fabric_name,
            add_switches_request_body=request_body,
        )
    except ApiException as e:
        if e.status == 400 and "already" in str(e.body).lower():
            print(f"  Switches already onboarded in '{fabric_name}', skipping.")
            return
        raise

    print(f"  {len(switches)} switch(es) submitted for onboarding into '{fabric_name}'.")


# ──────────────────────────────────────────────────────────────────────────────
# Operation: Create VRFs
# ──────────────────────────────────────────────────────────────────────────────

def op_create_vrfs(client, data: dict):
    """Create VRFs in the fabric."""
    fabric_name = data["fabric"]["name"]
    vrfs_data = data.get("vrfs", [])

    if not vrfs_data:
        print("  No VRFs defined in YAML, skipping.")
        return

    vrf_objects = []
    for vrf_def in vrfs_data:
        # Build core_data if provided
        core_data = None
        if "core_data" in vrf_def:
            core_data = VxlanCoreData(**vrf_def["core_data"])

        vrf = VxlanIbgpVrf(
            fabric_name=fabric_name,
            vrf_name=vrf_def["vrf_name"],
            vrf_type=vrf_def.get("vrf_type", "vxlanIbgp"),
            vrf_id=vrf_def.get("vrf_id"),
            vlan_id=vrf_def.get("vlan_id"),
            core_data=core_data,
        )
        vrf_schema = VrfSchema(actual_instance=vrf)
        vrf_objects.append(vrf_schema)

    request = CreateVrfsRequest(vrfs=vrf_objects)
    vrfs_api = VRFsAndNetworksApi(client)
    try:
        result = vrfs_api.create_vrfs(
            fabric_name=fabric_name,
            create_vrfs_request=request,
        )
        print(f"  {len(vrf_objects)} VRF(s) created in '{fabric_name}'.")
        return result
    except ApiException as e:
        if e.status != 400 or "already" not in str(e.body).lower():
            raise

    # One or more VRFs already exist — create-or-replace each individually
    created = 0
    updated = 0
    for vrf_def, vrf_schema in zip(vrfs_data, vrf_objects):
        vrf_name = vrf_def["vrf_name"]
        try:
            vrfs_api.create_vrfs(
                fabric_name=fabric_name,
                create_vrfs_request=CreateVrfsRequest(vrfs=[vrf_schema]),
            )
            created += 1
        except ApiException as e2:
            if e2.status == 400 and "already" in str(e2.body).lower():
                vrfs_api.replace_vrf(
                    fabric_name=fabric_name,
                    vrf_name=vrf_name,
                    vrf_schema=vrf_schema,
                )
                updated += 1
            else:
                raise
    print(f"  VRFs in '{fabric_name}': {created} created, {updated} updated.")


# ──────────────────────────────────────────────────────────────────────────────
# Operation: Create Networks
# ──────────────────────────────────────────────────────────────────────────────

def op_create_networks(client, data: dict):
    """Create overlay networks in the fabric."""
    fabric_name = data["fabric"]["name"]
    networks_data = data.get("networks", [])

    if not networks_data:
        print("  No networks defined in YAML, skipping.")
        return

    from cisco.nd_manage.models import DefaultL3Data

    network_objects = []
    for net_def in networks_data:
        # Build L3 data if provided
        l3_data = None
        if "l3_data" in net_def:
            l3_data = DefaultL3Data(**net_def["l3_data"])

        network = SchemasVxlanIbgp(
            fabric_name=fabric_name,
            network_name=net_def["network_name"],
            vrf_name=net_def["vrf_name"],
            network_type=net_def.get("network_type", "vxlanIbgp"),
            network_id=net_def.get("network_id"),
            vlan_id=net_def.get("vlan_id"),
            l3_data=l3_data,
        )
        network_base = NetworkBase(actual_instance=network)
        network_objects.append(network_base)

    request = CreateNetworksRequest(networks=network_objects)
    networks_api = VRFsAndNetworksApi(client)
    try:
        result = networks_api.create_networks(
            fabric_name=fabric_name,
            create_networks_request=request,
        )
        print(f"  {len(network_objects)} network(s) created in '{fabric_name}'.")
        return result
    except ApiException as e:
        if e.status != 400 or "already" not in str(e.body).lower():
            raise

    # One or more networks already exist — create-or-replace each individually
    created = 0
    updated = 0
    for net_def, network_base in zip(networks_data, network_objects):
        net_name = net_def["network_name"]
        try:
            networks_api.create_networks(
                fabric_name=fabric_name,
                create_networks_request=CreateNetworksRequest(networks=[network_base]),
            )
            created += 1
        except ApiException as e2:
            if e2.status == 400 and "already" in str(e2.body).lower():
                networks_api.replace_network(
                    fabric_name=fabric_name,
                    network_name=net_name,
                    network_base=network_base,
                )
                updated += 1
            else:
                raise
    print(f"  Networks in '{fabric_name}': {created} created, {updated} updated.")


# ──────────────────────────────────────────────────────────────────────────────
# Operation: Attach VRFs to Switches
# ──────────────────────────────────────────────────────────────────────────────

def op_attach_vrfs(client, data: dict):
    """Attach VRFs to switches."""
    fabric_name = data["fabric"]["name"]
    attachments_data = data.get("vrf_attachments", [])

    if not attachments_data:
        print("  No VRF attachments defined in YAML, skipping.")
        return

    attachment_objects = []
    for att_def in attachments_data:
        for sw in att_def.get("switches", []):
            instance_values = None
            if "instance_values" in sw:
                instance_values = VrfAttachmentInstanceValues(**sw["instance_values"])

            attachment = VrfAttachment(
                vrf_name=att_def["vrf_name"],
                switch_id=sw["switch_id"],
                vlan_id=sw.get("vlan_id"),
                attach=sw.get("attach", True),
                instance_values=instance_values,
            )
            attachment_objects.append(attachment)

    payload = VrfAttachDetachPayload(attachments=attachment_objects)
    vrfs_api = VRFsAndNetworksApi(client)
    try:
        result = vrfs_api.execute_attach_detach_vrfs(
            fabric_name=fabric_name,
            vrf_attach_detach_payload=payload,
        )
    except ApiException as e:
        if e.status == 400 and "already" in str(e.body).lower():
            print(f"  VRF attachment(s) already exist in '{fabric_name}', skipping.")
            return None
        raise

    # Print per-attachment results from 207 multi-status response
    if result and result.results:
        for r in result.results:
            status_str = r.status.value if r.status else "unknown"
            msg = f"    {r.vrf_name} -> {r.switch_id or r.switch_name}: {status_str}"
            if r.message:
                msg += f" ({r.message})"
            print(msg)
    print(f"  {len(attachment_objects)} VRF attachment(s) submitted in '{fabric_name}'.")
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Operation: Attach Networks to Switches
# ──────────────────────────────────────────────────────────────────────────────

def op_attach_networks(client, data: dict):
    """Attach networks to switches with optional port assignments."""
    fabric_name = data["fabric"]["name"]
    attachments_data = data.get("network_attachments", [])

    if not attachments_data:
        print("  No network attachments defined in YAML, skipping.")
        return

    attachment_objects = []
    for att_def in attachments_data:
        for sw in att_def.get("switches", []):
            # Build interface list if ports are specified
            interfaces = None
            if "interfaces" in sw:
                interfaces = []
                for intf in sw["interfaces"]:
                    mode = intf.get("mode", "access")
                    if mode == "trunk":
                        intf_schema = SchemasTrunkInterface(
                            interface_range=intf["interface_range"],
                            mode="trunk",
                            native_vlan=intf.get("native_vlan", False),
                        )
                    else:
                        intf_schema = SchemasAccessInterface(
                            interface_range=intf["interface_range"],
                            mode="access",
                        )
                    interfaces.append(
                        NetworkAttachmentInterfaces(intf_schema)
                    )

            attachment = NetworkAttachment(
                network_name=att_def["network_name"],
                switch_id=sw["switch_id"],
                vlan_id=sw.get("vlan_id"),
                attach=sw.get("attach", True),
                interfaces=interfaces,
            )
            attachment_objects.append(attachment)

    payload = NetworAttachDetachPayload(attachments=attachment_objects)
    networks_api = VRFsAndNetworksApi(client)
    try:
        result = networks_api.execute_attach_networks(
            fabric_name=fabric_name,
            networ_attach_detach_payload=payload,
        )
    except ApiException as e:
        if e.status == 400 and "already" in str(e.body).lower():
            print(f"  Network attachment(s) already exist in '{fabric_name}', skipping.")
            return None
        raise

    # Print per-attachment results from 207 multi-status response
    if result and hasattr(result, 'results') and result.results:
        for r in result.results:
            status_str = r.status.value if hasattr(r, 'status') and r.status else "unknown"
            name = getattr(r, 'network_name', None) or getattr(r, 'vrf_name', None) or "?"
            switch = getattr(r, 'switch_id', None) or getattr(r, 'switch_name', None) or "?"
            msg = f"    {name} -> {switch}: {status_str}"
            if hasattr(r, 'message') and r.message:
                msg += f" ({r.message})"
            print(msg)
    print(f"  {len(attachment_objects)} network attachment(s) submitted in '{fabric_name}'.")
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Operation: Deploy VRFs and Networks
# ──────────────────────────────────────────────────────────────────────────────

def op_deploy(client, data: dict):
    """Deploy pending configuration to out-of-sync switches in the fabric.

    Queries the fabric for all switches, filters to those with pending or
    out-of-sync config status, then issues a switch-level config deploy.
    The controller pushes only pending config — in-sync switches are skipped.
    This covers VRFs, networks, interfaces, and any other pending changes.
    """
    fabric_name = data["fabric"]["name"]
    inv_api = InventoryApi(client)
    deploy_api = ConfigurationDeploymentApi(client)

    # Get all switches in the fabric
    resp = inv_api.list_fabric_switches(fabric_name=fabric_name)
    all_switches = resp.switches or []

    if not all_switches:
        print("  No switches found in fabric, nothing to deploy.")
        return

    # Filter to switches that have pending/out-of-sync config
    # configSyncStatus is at: sw.additional_data.actual_instance.config_sync_status
    pending_statuses = {"pending", "outofsync", "failed"}
    pending_switches = []
    in_sync_switches = []
    for sw in all_switches:
        status = None
        if sw.additional_data and sw.additional_data.actual_instance:
            css = sw.additional_data.actual_instance.config_sync_status
            if css:
                status = css.value  # e.g. "inSync", "outOfSync", "pending"
        if status and status.lower().replace("-", "").replace("_", "") in pending_statuses:
            pending_switches.append((sw, status))
        else:
            in_sync_switches.append((sw, status or "unknown"))

    if pending_switches:
        switch_ids = [sw.switch_id for sw, _ in pending_switches]
        print(f"  {len(pending_switches)}/{len(all_switches)} switch(es) have pending config:")
        for sw, status in pending_switches:
            print(f"    {sw.switch_id} ({sw.hostname}): {status}")
        if in_sync_switches:
            print(f"  {len(in_sync_switches)} switch(es) already in-sync, skipping.")
    else:
        # All switches are in-sync
        print(f"  All {len(all_switches)} switch(es) are in-sync. Nothing to deploy.")
        for sw, status in in_sync_switches:
            print(f"    {sw.switch_id} ({sw.hostname}): {status}")
        return

    print(f"  Deploying config to: {switch_ids}")
    request = ExecuteSwitchConfigDeployRequest(switch_ids=switch_ids)
    try:
        result = deploy_api.execute_switch_config_deploy(
            fabric_name=fabric_name,
            execute_switch_config_deploy_request=request,
        )
        # 207 multi-status response — print per-switch results
        if hasattr(result, 'switches') and result.switches:
            for sw in result.switches:
                sw_dict = sw.to_dict() if hasattr(sw, 'to_dict') else sw
                print(f"    {sw_dict}")
        else:
            print(f"    Deploy response: {result}")
    except ApiException as e:
        print(f"  WARNING: Switch deploy returned {e.status}: {e.body}", file=sys.stderr)


# ──────────────────────────────────────────────────────────────────────────────
# Operation: Reconcile (remove stale VRFs/networks not in YAML)
# ──────────────────────────────────────────────────────────────────────────────

def op_reconcile(client, data: dict, dry_run: bool = False):
    """Remove VRFs and networks from the controller that are not in the YAML.

    Compares the YAML desired state to the controller's current state and
    removes anything on the controller that isn't declared in the YAML.

    Order: detach networks → detach VRFs → deploy → delete networks → delete VRFs.
    """
    fabric_name = data["fabric"]["name"]
    vrfs_api = VRFsAndNetworksApi(client)
    inventory_api = InventoryApi(client)

    # ── Gather desired state from YAML ──
    desired_vrfs = {v["vrf_name"] for v in data.get("vrfs", [])}
    desired_networks = {n["network_name"] for n in data.get("networks", [])}

    # ── Gather current state from controller ──
    print("  Querying controller state...")

    current_vrfs = set()
    try:
        vrf_response = vrfs_api.list_vrfs(fabric_name=fabric_name)
        if vrf_response and vrf_response.vrfs:
            for vrf_schema in vrf_response.vrfs:
                inst = vrf_schema.actual_instance
                if inst and hasattr(inst, "vrf_name"):
                    current_vrfs.add(inst.vrf_name)
    except ApiException as e:
        if e.status != 404:
            raise

    current_networks = set()
    try:
        net_response = vrfs_api.list_networks(fabric_name=fabric_name)
        if net_response and net_response.networks:
            for net_base in net_response.networks:
                inst = net_base.actual_instance
                if inst and hasattr(inst, "network_name"):
                    current_networks.add(inst.network_name)
    except ApiException as e:
        if e.status != 404:
            raise

    # Get all switch serial numbers in the fabric (for detach operations)
    fabric_switches = []
    try:
        sw_response = inventory_api.list_all_switches(fabric_name=fabric_name)
        if sw_response and sw_response.switches:
            for sw in sw_response.switches:
                if sw.serial_number:
                    fabric_switches.append(sw.serial_number)
    except ApiException as e:
        if e.status != 404:
            raise

    # ── Compute diff ──
    stale_networks = current_networks - desired_networks
    stale_vrfs = current_vrfs - desired_vrfs

    if not stale_networks and not stale_vrfs:
        print("  Controller is in sync with YAML. Nothing to remove.")
        return

    # ── Report ──
    if stale_networks:
        print(f"  Networks to remove: {', '.join(sorted(stale_networks))}")
    if stale_vrfs:
        print(f"  VRFs to remove: {', '.join(sorted(stale_vrfs))}")
    if fabric_switches:
        print(f"  Fabric switches: {', '.join(fabric_switches)}")

    if dry_run:
        print("\n  [DRY-RUN] No changes made. Rerun without --dry-run to execute.")
        return

    # ── Step 1: Detach stale networks from all switches ──
    if stale_networks and fabric_switches:
        net_attachments = []
        for net_name in stale_networks:
            for sw_serial in fabric_switches:
                net_attachments.append(NetworkAttachment(
                    network_name=net_name,
                    switch_id=sw_serial,
                    attach=False,
                ))
        payload = NetworAttachDetachPayload(attachments=net_attachments)
        try:
            result = vrfs_api.execute_attach_networks(
                fabric_name=fabric_name,
                networ_attach_detach_payload=payload,
            )
            if result and result.results:
                for r in result.results:
                    status_str = r.status.value if r.status else "unknown"
                    if r.message:
                        print(f"    {r.network_name} -> {r.switch_id}: {status_str} ({r.message})")
        except ApiException as e:
            print(f"  WARNING: Network detach returned {e.status}: {e.body}", file=sys.stderr)
        else:
            print(f"  Network detachment(s) submitted.")

    # ── Step 2: Detach stale VRFs from all switches ──
    if stale_vrfs and fabric_switches:
        vrf_attachments = []
        for vrf_name in stale_vrfs:
            for sw_serial in fabric_switches:
                vrf_attachments.append(VrfAttachment(
                    vrf_name=vrf_name,
                    switch_id=sw_serial,
                    attach=False,
                ))
        payload = VrfAttachDetachPayload(attachments=vrf_attachments)
        try:
            result = vrfs_api.execute_attach_detach_vrfs(
                fabric_name=fabric_name,
                vrf_attach_detach_payload=payload,
            )
            if result and result.results:
                for r in result.results:
                    status_str = r.status.value if r.status else "unknown"
                    if r.message:
                        print(f"    {r.vrf_name} -> {r.switch_id}: {status_str} ({r.message})")
        except ApiException as e:
            print(f"  WARNING: VRF detach returned {e.status}: {e.body}", file=sys.stderr)
        else:
            print(f"  VRF detachment(s) submitted.")

    # ── Step 3: Deploy detach operations ──
    if stale_networks:
        try:
            vrfs_api.execute_deploy_networks(
                fabric_name=fabric_name,
                network_switches_list=NetworkSwitchesList(network_names=list(stale_networks)),
            )
        except ApiException as e:
            print(f"  WARNING: Network deploy (detach) returned {e.status}: {e.body}", file=sys.stderr)
        else:
            print(f"  Network detach deployment initiated.")

    if stale_vrfs:
        try:
            vrfs_api.execute_deploy_vrfs(
                fabric_name=fabric_name,
                deploy_vrfs_request=DeployVrfsRequest(vrf_names=list(stale_vrfs)),
            )
        except ApiException as e:
            print(f"  WARNING: VRF deploy (detach) returned {e.status}: {e.body}", file=sys.stderr)
        else:
            print(f"  VRF detach deployment initiated.")

    # ── Step 4: Delete stale network definitions ──
    for net_name in sorted(stale_networks):
        try:
            vrfs_api.delete_network(fabric_name=fabric_name, network_name=net_name)
            print(f"  Network '{net_name}' deleted.")
        except ApiException as e:
            if e.status == 404:
                print(f"  Network '{net_name}' not found, skipping.")
            else:
                print(f"  WARNING: Delete network '{net_name}' returned {e.status}: {e.body}", file=sys.stderr)

    # ── Step 5: Delete stale VRF definitions ──
    for vrf_name in sorted(stale_vrfs):
        try:
            vrfs_api.delete_vrf(fabric_name=fabric_name, vrf_name=vrf_name)
            print(f"  VRF '{vrf_name}' deleted.")
        except ApiException as e:
            if e.status == 404:
                print(f"  VRF '{vrf_name}' not found, skipping.")
            else:
                print(f"  WARNING: Delete VRF '{vrf_name}' returned {e.status}: {e.body}", file=sys.stderr)


# ──────────────────────────────────────────────────────────────────────────────
# Operation: Configure Interfaces
# ──────────────────────────────────────────────────────────────────────────────

def op_configure_interfaces(client, data: dict):
    """Configure switch interfaces."""
    fabric_name = data["fabric"]["name"]
    interfaces_data = data.get("interfaces", [])

    if not interfaces_data:
        print("  No interfaces defined in YAML, skipping.")
        return

    from cisco.nd_manage.models import (
        CreateInterfaceEthernet,
        CreateInterfaceEthernetAccess,
        CreateInterfaceEthernetAccessNexus,
        CreateInterfaceEthernetAccessNexusType,
        CreateInterfaceEthernetAccessSubType,
        CreateInterfaceEthernetTrunk,
        CreateInterfaceEthernetTrunkNexus,
        CreateInterfaceEthernetTrunkNexusType,
        CreateInterfaceEthernetTrunkSubType,
        CreateInterfaceEthernetType,
        CreateInterfaceSubType,
        IntAccessHostTemplate,
        InterfaceEthernetAccessNexusUniqueSubType,
        InterfacePost,
        InterfacePut,
        IntTrunkHostTemplate,
        InterfaceEthernetTrunkNexusSubType,
    )

    interfaces_api = InterfacesApi(client)

    for switch_def in interfaces_data:
        switch_serial = switch_def["switch_serial"]
        intf_posts = []

        for eth in switch_def.get("ethernet", []):
            mode = eth.get("mode", "access")

            intf_name = eth["name"]

            if mode == "access":
                access_policy = IntAccessHostTemplate(
                    policy_type=InterfaceEthernetAccessNexusUniqueSubType.ACCESSHOST,
                    access_vlan=eth.get("access_vlan"),
                    admin_state=eth.get("admin_state", True),
                    extra_config=eth.get("description", ""),
                )
                access_nexus_type = CreateInterfaceEthernetAccessNexusType(
                    actual_instance=access_policy
                )
                access_nexus = CreateInterfaceEthernetAccessNexus(
                    network_os_type=CreateInterfaceEthernetAccessSubType.NX_MINUS_OS,
                    policy=access_nexus_type,
                )
                access_type = CreateInterfaceEthernetAccessType(
                    actual_instance=access_nexus
                )
                access_config = CreateInterfaceEthernetAccess(
                    mode=CreateInterfaceEthernetSubType.ACCESS,
                    network_os=access_type,
                )
                ethernet_type = CreateInterfaceEthernetType(
                    actual_instance=access_config
                )
                ethernet = CreateInterfaceEthernet(
                    interface_type=CreateInterfaceSubType.ETHERNET,
                    config_data=ethernet_type,
                )
                intf_post = InterfacePost(
                    actual_instance=ethernet,
                    interface_name=intf_name,
                )
                intf_posts.append(intf_post)

            elif mode == "trunk":
                trunk_policy = IntTrunkHostTemplate(
                    policy_type=InterfaceEthernetTrunkNexusSubType.TRUNKHOST,
                    allowed_vlans=eth.get("trunk_allowed_vlans", "none"),
                    admin_state=eth.get("admin_state", True),
                    extra_config=eth.get("description", ""),
                )
                trunk_nexus_type = CreateInterfaceEthernetTrunkNexusType(
                    actual_instance=trunk_policy
                )
                trunk_nexus = CreateInterfaceEthernetTrunkNexus(
                    network_os_type=CreateInterfaceEthernetTrunkSubType.NX_MINUS_OS,
                    policy=trunk_nexus_type,
                )
                trunk_type = CreateInterfaceEthernetTrunkType(
                    actual_instance=trunk_nexus
                )
                trunk_config = CreateInterfaceEthernetTrunk(
                    mode=CreateInterfaceEthernetSubType.TRUNK,
                    network_os=trunk_type,
                )
                ethernet_type = CreateInterfaceEthernetType(
                    actual_instance=trunk_config
                )
                ethernet = CreateInterfaceEthernet(
                    interface_type=CreateInterfaceSubType.ETHERNET,
                    config_data=ethernet_type,
                )
                intf_post = InterfacePost(
                    actual_instance=ethernet,
                    interface_name=intf_name,
                )
                intf_posts.append(intf_post)

        if intf_posts:
            request = CreateInterfaceRequest(interfaces=intf_posts)
            try:
                interfaces_api.create_interface(
                    fabric_name=fabric_name,
                    switch_id=switch_serial,
                    create_interface_request=request,
                )
                print(f"  {len(intf_posts)} interface(s) created on switch '{switch_serial}'.")
            except ApiException as e:
                if e.status != 400 or "already" not in str(e.body).lower():
                    raise
                # Interfaces already exist — update each individually
                updated = 0
                for intf_post in intf_posts:
                    interfaces_api.update_interface(
                        fabric_name=fabric_name,
                        switch_id=switch_serial,
                        interface_name=intf_post.interface_name,
                        interface_put=InterfacePut(
                            actual_instance=intf_post.actual_instance,
                            interface_name=intf_post.interface_name,
                            switch_id=switch_serial,
                        ),
                    )
                    updated += 1
                print(f"  {updated} interface(s) updated on switch '{switch_serial}'.")


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    data = load_data(args.data)

    conn = data["connection"]

    # Resolve connection parameters (CLI overrides > YAML > env vars)
    host = args.host or conn["host"]
    user = args.user or conn.get("user", "admin")
    domain = conn.get("domain", "local")
    verify_ssl = args.verify_ssl if args.verify_ssl is not None else conn.get("verify_ssl", False)

    api_key = args.api_key or os.environ.get("ND_API_KEY")
    password = args.password or os.environ.get("ND_PASSWORD")

    if not api_key and not password:
        print("ERROR: Provide --api-key / ND_API_KEY or --password / ND_PASSWORD.", file=sys.stderr)
        sys.exit(1)

    # Suppress insecure request warnings when SSL verification is disabled
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if api_key:
        print(f"Using API key for Nexus Dashboard at {host}...")
        token = api_key
    else:
        print(f"Logging into Nexus Dashboard at {host}...")
        token = login(host, user, password, domain, verify_ssl)
        print("Login successful.")
    print()

    operation = args.operation
    run_all = operation == "all"

    with get_manage_client(host, token, verify_ssl) as client:

        if run_all or operation == "fabric":
            if "fabric" in data:
                print("[1/9] Creating fabric...")
                op_create_fabric(client, data)
                print()

        if run_all or operation == "inventory":
            if "inventory" in data:
                print("[2/9] Onboarding switches...")
                op_onboard_switches(client, data)
                print()

        if run_all or operation == "vrfs":
            if "vrfs" in data:
                print("[3/9] Creating VRFs...")
                op_create_vrfs(client, data)
                print()

        if run_all or operation == "networks":
            if "networks" in data:
                print("[4/9] Creating networks...")
                op_create_networks(client, data)
                print()

        if run_all or operation == "attach_vrfs":
            if "vrf_attachments" in data:
                print("[5/9] Attaching VRFs to switches...")
                op_attach_vrfs(client, data)
                print()

        if run_all or operation == "attach_nets":
            if "network_attachments" in data:
                print("[6/9] Attaching networks to switches...")
                op_attach_networks(client, data)
                print()

        if run_all or operation == "deploy":
            print("[7/9] Deploying configs to switches...")
            op_deploy(client, data)
            print()

        if run_all or operation == "interfaces":
            if "interfaces" in data:
                print("[8/9] Configuring interfaces...")
                op_configure_interfaces(client, data)
                print()

        if operation == "reconcile":
            print("[9/9] Reconciling controller state with YAML...")
            op_reconcile(client, data, dry_run=args.dry_run)
            print()

    print("Done.")


if __name__ == "__main__":
    main()
