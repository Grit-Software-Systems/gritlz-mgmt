import json
import sys
from pathlib import Path
import uuid
import requests
from azure.identity import DefaultAzureCredential

# Configuration: resource types to pre-flight
HIGH_RISK_RESOURCES = [
    "azurerm_firewall",
    "azurerm_application_gateway",
    "azurerm_lb",
    "azurerm_bastion_host"
]

VALID_ACTIONS = {"create", "update"}

# Load Terraform plan JSON
tfplan_path = Path("tfPlan.json")
if not tfplan_path.exists():
    print("Terraform plan JSON not found. Run `terraform show -json tfplan.binary > tfplan.json` first.")
    sys.exit(1)

with open(tfplan_path) as f:
    plan = json.load(f)


def generate_arm_template(resource):
    """
    Generate a minimal ARM template for the resource for validation.
    Only includes required fields: type, apiVersion, name, location, sku/tier where applicable.
    """
    res_type = resource["type"]
    res_name = resource["address"].replace(
        ".", "-").replace("[", "-").replace("]", "")
    location = resource["change"]["after"].get("location", "eastus")

    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "resources": [
            {
                "type": None,
                "apiVersion": "2022-08-01",
                "name": res_name,
                "location": location
            }
        ]
    }

    res = template["resources"][0]

    if res_type == "azurerm_firewall":
        res["type"] = "Microsoft.Network/azureFirewalls"
        sku = resource["change"]["after"].get("sku_name", "AZFW_VNet")
        res["sku"] = {"name": sku, "tier": "Standard"}
    elif res_type == "azurerm_application_gateway":
        res["type"] = "Microsoft.Network/applicationGateways"
        sku_name = resource["change"]["after"].get("sku_name", "WAF_v2")
        res["sku"] = {"name": sku_name, "tier": "WAF"}
    elif res_type == "azurerm_lb":
        res["type"] = "Microsoft.Network/loadBalancers"
        sku_name = resource["change"]["after"].get("sku", "Standard")
        res["sku"] = {"name": sku_name}
    elif res_type == "azurerm_bastion_host":
        res["type"] = "Microsoft.Network/bastionHosts"
    else:
        raise ValueError(f"Unknown resource type {res_type}")

    return template


def select_subscription():
    """
    Prompts the user to select a subscription from the available subscriptions.
    Returns the selected subscription ID.
    """
    credential = DefaultAzureCredential()
    token = credential.get_token("https://management.azure.com/.default").token
    url = "https://management.azure.com/subscriptions?api-version=2020-01-01"
    headers = {"Authorization": f"Bearer {token}"}

    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    subscriptions = resp.json().get("value", [])

    if not subscriptions:
        raise RuntimeError(
            "No subscriptions found for the current credentials.")

    print("Available subscriptions:")
    for idx, sub in enumerate(subscriptions, 1):
        print(f"{idx}. {sub['displayName']} ({sub['subscriptionId']})")

    choice = input(f"Select a subscription [1-{len(subscriptions)}]: ").strip()
    try:
        choice_idx = int(choice) - 1
        if choice_idx < 0 or choice_idx >= len(subscriptions):
            raise ValueError()
    except ValueError:
        raise RuntimeError("Invalid subscription selection.")

    return subscriptions[choice_idx]["subscriptionId"]


def run_arm_validate(subscription_id: str, resource_group: str, location: str, template: dict):
    """
    Calls ARM deployment validate directly.
    Returns (success: bool, message: str)
    """
    credential = DefaultAzureCredential()
    token = credential.get_token("https://management.azure.com/.default").token

    deployment_name = f"preflight-{uuid.uuid4()}"
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Resources/deployments/{deployment_name}"
        f"/validate?api-version=2021-04-01"
    )

    body = {
        "properties": {
            "mode": "Incremental",
            "template": template,
            "parameters": {},
        }
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    resp = requests.post(url, headers=headers, json=body)
    payload = resp.json()

    if resp.status_code == 200:
        return True, "Validation succeeded"

    # Real ARM failure (SKU, zone, region, capacity, etc.)
    error = payload.get("error", payload)
    return False, json.dumps(error, indent=2)


# Ask the user to choose subscription
subscription_id = select_subscription()

# Iterate resources in the plan
errors = []

for resource in plan.get("resource_changes", []):
    actions = set(resource["change"].get("actions", []))
    if resource["type"] in HIGH_RISK_RESOURCES and actions.intersection(VALID_ACTIONS):
        template = generate_arm_template(resource)
        location = template["resources"][0]["location"]

        after = resource["change"].get("after", {})
        zones = after.get("zones", [])
        sku = after.get("sku_name") or after.get("sku") or "unknown"

        success, msg = run_arm_validate(
            subscription_id=subscription_id,
            resource_group="preflight-rg",
            location=location,
            template=template,
        )

        if not success:
            errors.append(
                f"{resource['address']} failed validation\n"
                f"  Location : {location}\n"
                f"  SKU      : {sku}\n"
                f"  Zones    : {zones if zones else 'none'}\n"
                f"  Error    : {msg}\n"
            )

if errors:
    print("Pre-flight validation failed for the following resources:")
    for e in errors:
        print(e)
    sys.exit(1)
else:
    print("Pre-flight validation passed for all high-risk resources!")
