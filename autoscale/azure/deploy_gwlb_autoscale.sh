#!/usr/bin/env bash
set -euo pipefail

AZURE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${AZURE_DIR}/../.." && pwd)"

RG="${RG:-himkotha-py-as-tdv-rg}"
LOCATION="${LOCATION:-eastus}"
PREFIX="${PREFIX:-himpyas}"
SUBSCRIPTION_ID="${SUBSCRIPTION_ID:-$(az account show --query id -o tsv)}"

VNET_RG="${VNET_RG:-$RG}"
VNET_NAME="${VNET_NAME:-himpyas-vnet}"
VNET_CIDR="${VNET_CIDR:-10.80.0.0/16}"
SUBNET1="${SUBNET1:-mgmt}"
SUBNET2="${SUBNET2:-diag}"
SUBNET3="${SUBNET3:-outside}"
NUMBER_OF_INTERFACES="${NUMBER_OF_INTERFACES:-3}"
DIAGNOSTIC="${DIAGNOSTIC:-OFF}"

FUNCTION_HOSTING_PLAN="${FUNCTION_HOSTING_PLAN:-premium}"
FUNCTION_APP_SUBNET="${FUNCTION_APP_SUBNET:-FunctionApp}"
FUNCTION_APP_SUBNET_CIDR="${FUNCTION_APP_SUBNET_CIDR:-10.80.5.0/24}"

SOFTWARE_VERSION="${SOFTWARE_VERSION:-10.00.140}"
FTD_LICENSING_SKU="${FTD_LICENSING_SKU:-ftdv-azure-payg}"
CUSTOM_IMAGE_ID="${CUSTOM_IMAGE_ID:-}"
BOOT_MODE="${BOOT_MODE:-uefi}"
INTERFACE_NAME_PREFIX="${INTERFACE_NAME_PREFIX:-}"
VM_SIZE="${VM_SIZE:-Standard_D8s_v5}"
ENABLE_SECURE_BOOT="${ENABLE_SECURE_BOOT:-false}"
FTD_VM_USER="${FTD_VM_USER:-cisco}"
FTD_COUNT="${FTD_COUNT:-2}"
MIN_FTD_COUNT="${MIN_FTD_COUNT:-2}"
MAX_FTD_COUNT="${MAX_FTD_COUNT:-10}"

FMC_DEPLOY_IP="${FMC_DEPLOY_IP:-10.80.1.10}"
FMC_API_IP="${FMC_API_IP:-20.102.120.74}"
FMC_USER="${FMC_USER:-admin}"
REGISTRATION_USING_PUBLIC_FMC_IP="${REGISTRATION_USING_PUBLIC_FMC_IP:-NO}"
POLICY_NAME="${POLICY_NAME:-himpyas-policy}"
DEVICE_GROUP_NAME="${DEVICE_GROUP_NAME:-himpyas-device-group}"
OUTSIDE_ZONE_NAME="${OUTSIDE_ZONE_NAME:-outside}"
OUTSIDE_GATEWAY_IP="${OUTSIDE_GATEWAY_IP:-10.80.3.1}"
GWLB_IP="${GWLB_IP:-10.80.3.250}"
PERFORMANCE_TIER="${PERFORMANCE_TIER:-FTDv30}"
LICENSE_CAPABILITY="${LICENSE_CAPABILITY:-BASE, MALWARE, URLFilter, THREAT}"

HEALTH_CHECK_PORT="${HEALTH_CHECK_PORT:-7777}"
INIT_DEPLOYMENT_MODE="${INIT_DEPLOYMENT_MODE:-BULK}"
SCALING_POLICY="${SCALING_POLICY:-POLICY-1}"
SCALING_METRICS_LIST="${SCALING_METRICS_LIST:-CPU}"
CPU_SCALE_IN_THRESHOLD="${CPU_SCALE_IN_THRESHOLD:-10}"
CPU_SCALE_OUT_THRESHOLD="${CPU_SCALE_OUT_THRESHOLD:-80}"
MEMORY_SCALE_IN_THRESHOLD="${MEMORY_SCALE_IN_THRESHOLD:-0}"
MEMORY_SCALE_OUT_THRESHOLD="${MEMORY_SCALE_OUT_THRESHOLD:-0}"
METRICS_AVERAGE_DURATION="${METRICS_AVERAGE_DURATION:-1}"
AUTO_DELETE_UNHEALTHY_VM="${AUTO_DELETE_UNHEALTHY_VM:-NO}"

FMC_SECRET_FILE="${FMC_SECRET_FILE:-/tmp/himpyas-fmcv-secrets.env}"
FTD_SECRET_FILE="${FTD_SECRET_FILE:-/tmp/himpyas-autoscale-secrets.env}"
PARAMS_FILE="${PARAMS_FILE:-/tmp/${PREFIX}-gwlb-autoscale-params.json}"
LOGIC_BODY_FILE="${LOGIC_BODY_FILE:-/tmp/${PREFIX}-logic-app-body.json}"
FUNCTION_PACKAGE_FILE="${FUNCTION_PACKAGE_FILE:-${AZURE_DIR}/target/autoscale_function_linux.zip}"
FUNCTION_PACKAGE_BUILD_PLATFORM="${FUNCTION_PACKAGE_BUILD_PLATFORM:-manylinux2014_x86_64}"
FUNCTION_PACKAGE_PYTHON_VERSION="${FUNCTION_PACKAGE_PYTHON_VERSION:-3.11}"
FUNCTION_PACKAGE_ABI="${FUNCTION_PACKAGE_ABI:-cp311}"
CLEAN_FMC_DEVICES="${CLEAN_FMC_DEVICES:-true}"
ENABLE_LOGIC_APP="${ENABLE_LOGIC_APP:-true}"
SCALE_VMSS="${SCALE_VMSS:-true}"

read_secret() {
  local key="$1"
  local file="$2"
  if [[ -f "$file" ]]; then
    awk -F= -v key="$key" '$1 == key {print substr($0, length(key) + 2)}' "$file" | tail -n 1
  fi
}

FMC_PASS="${FMC_PASS:-$(read_secret FMC_PASS "$FMC_SECRET_FILE")}"
FTD_PASS="${FTD_PASS:-$(read_secret FTD_PASS "$FTD_SECRET_FILE")}"
if [[ -z "${FTD_PASS}" ]]; then
  FTD_PASS="${FTD_ADMIN_PASSWORD:-}"
fi

if [[ -z "${FMC_PASS}" ]]; then
  echo "FMC_PASS is required. Set FMC_PASS or provide ${FMC_SECRET_FILE}." >&2
  exit 1
fi

if [[ -z "${FTD_PASS}" ]]; then
  echo "FTD_PASS is required. Set FTD_PASS or provide ${FTD_SECRET_FILE}." >&2
  exit 1
fi

export RG LOCATION PREFIX SUBSCRIPTION_ID
export VNET_RG VNET_NAME VNET_CIDR SUBNET1 SUBNET2 SUBNET3 NUMBER_OF_INTERFACES DIAGNOSTIC
export FUNCTION_HOSTING_PLAN FUNCTION_APP_SUBNET FUNCTION_APP_SUBNET_CIDR
export SOFTWARE_VERSION FTD_LICENSING_SKU CUSTOM_IMAGE_ID BOOT_MODE INTERFACE_NAME_PREFIX VM_SIZE ENABLE_SECURE_BOOT FTD_VM_USER
export FTD_COUNT MIN_FTD_COUNT MAX_FTD_COUNT FTD_PASS
export FMC_DEPLOY_IP FMC_API_IP FMC_USER FMC_PASS POLICY_NAME DEVICE_GROUP_NAME OUTSIDE_ZONE_NAME OUTSIDE_GATEWAY_IP GWLB_IP
export REGISTRATION_USING_PUBLIC_FMC_IP
export PERFORMANCE_TIER LICENSE_CAPABILITY
export HEALTH_CHECK_PORT INIT_DEPLOYMENT_MODE SCALING_POLICY SCALING_METRICS_LIST
export CPU_SCALE_IN_THRESHOLD CPU_SCALE_OUT_THRESHOLD MEMORY_SCALE_IN_THRESHOLD MEMORY_SCALE_OUT_THRESHOLD
export METRICS_AVERAGE_DURATION AUTO_DELETE_UNHEALTHY_VM

echo "Using subscription ${SUBSCRIPTION_ID}"
az account set --subscription "${SUBSCRIPTION_ID}"

cleanup_fmc_devices() {
  if [[ "${CLEAN_FMC_DEVICES}" != "true" ]]; then
    return
  fi

  FMC_API_IP="${FMC_API_IP}" FMC_USER="${FMC_USER}" FMC_PASS="${FMC_PASS}" PREFIX="${PREFIX}" python3 - <<'PY'
import os
import requests

requests.packages.urllib3.disable_warnings()
fmc_ip = os.environ["FMC_API_IP"]
user = os.environ["FMC_USER"]
password = os.environ["FMC_PASS"]
prefix = os.environ["PREFIX"]

headers = {"Content-Type": "application/json"}
auth = requests.post(
    f"https://{fmc_ip}/api/fmc_platform/v1/auth/generatetoken",
    auth=(user, password),
    headers=headers,
    verify=False,
    timeout=30,
)
auth.raise_for_status()
headers["X-auth-access-token"] = auth.headers["X-auth-access-token"]
domain_uuid = (
    auth.headers.get("DOMAIN_UUID")
    or auth.headers.get("domain_uuid")
    or "e276abec-e0f2-11e3-8169-6d9ed49b625f"
)
base_url = f"https://{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}"
devices = requests.get(
    f"{base_url}/devices/devicerecords?expanded=true&limit=1000",
    headers=headers,
    verify=False,
    timeout=30,
)
devices.raise_for_status()
for device in devices.json().get("items", []):
    name = device.get("name", "")
    if name.startswith(f"{prefix}-vmss"):
        delete = requests.delete(
            f"{base_url}/devices/devicerecords/{device['id']}",
            headers=headers,
            verify=False,
            timeout=60,
        )
        print(f"Deleted FMC device {name}: HTTP {delete.status_code}")
        delete.raise_for_status()
PY
}

render_parameters() {
  PARAMS_FILE="${PARAMS_FILE}" python3 - <<'PY'
import json
import os

def val(name):
    return os.environ[name]

params = {
    "resourceNamePrefix": {"value": val("PREFIX")},
    "virtualNetworkRg": {"value": val("VNET_RG")},
    "virtualNetworkName": {"value": val("VNET_NAME")},
    "virtualNetworkCidr": {"value": val("VNET_CIDR")},
    "subnet1": {"value": val("SUBNET1")},
    "subnet2": {"value": val("SUBNET2")},
    "subnet3": {"value": val("SUBNET3")},
    "subnet4": {"value": os.environ.get("SUBNET4", "")},
    "subnet5": {"value": os.environ.get("SUBNET5", "")},
    "subnet6": {"value": os.environ.get("SUBNET6", "")},
    "subnet7": {"value": os.environ.get("SUBNET7", "")},
    "subnet8": {"value": os.environ.get("SUBNET8", "")},
    "subnet9": {"value": os.environ.get("SUBNET9", "")},
    "subnet10": {"value": os.environ.get("SUBNET10", "")},
    "numberOfInterfaces": {"value": int(val("NUMBER_OF_INTERFACES"))},
    "diagnostic": {"value": val("DIAGNOSTIC")},
    "gatewayLoadBalancerIP": {"value": val("GWLB_IP")},
    "outsideNetworkGatewayIp": {"value": val("OUTSIDE_GATEWAY_IP")},
    "outsideZoneName": {"value": val("OUTSIDE_ZONE_NAME")},
    "functionHostingPlan": {"value": val("FUNCTION_HOSTING_PLAN")},
    "functionAppSubnet": {"value": val("FUNCTION_APP_SUBNET")},
    "functionAppSubnetCIDR": {"value": val("FUNCTION_APP_SUBNET_CIDR")},
    "vmSize": {"value": val("VM_SIZE")},
    "ftdVmManagementUserName": {"value": val("FTD_VM_USER")},
    "ftdVmManagementUserPassword": {"value": val("FTD_PASS")},
    "fmcIpAddress": {"value": val("FMC_DEPLOY_IP")},
    "registrationUsingPublicFMCIP": {"value": val("REGISTRATION_USING_PUBLIC_FMC_IP")},
    "fmcUserName": {"value": val("FMC_USER")},
    "fmcPassword": {"value": val("FMC_PASS")},
    "policyName": {"value": val("POLICY_NAME")},
    "deviceGroupName": {"value": val("DEVICE_GROUP_NAME")},
    "licenseCapability": {"value": val("LICENSE_CAPABILITY")},
    "performanceTier": {"value": val("PERFORMANCE_TIER")},
    "scalingMetricsList": {"value": val("SCALING_METRICS_LIST")},
    "cpuScaleInThreshold": {"value": val("CPU_SCALE_IN_THRESHOLD")},
    "cpuScaleOutThreshold": {"value": val("CPU_SCALE_OUT_THRESHOLD")},
    "memoryScaleInThreshold": {"value": val("MEMORY_SCALE_IN_THRESHOLD")},
    "memoryScaleOutThreshold": {"value": val("MEMORY_SCALE_OUT_THRESHOLD")},
    "minFtdCount": {"value": int(val("MIN_FTD_COUNT"))},
    "maxFtdCount": {"value": int(val("MAX_FTD_COUNT"))},
    "metricsAverageDuration": {"value": val("METRICS_AVERAGE_DURATION")},
    "initDeploymentMode": {"value": val("INIT_DEPLOYMENT_MODE")},
    "scalingPolicy": {"value": val("SCALING_POLICY")},
    "healthCheckPortNumber": {"value": val("HEALTH_CHECK_PORT")},
    "AutoDeleteUnhealthyVm": {"value": val("AUTO_DELETE_UNHEALTHY_VM")},
}

if os.environ.get("CUSTOM_IMAGE_ID"):
    params.update({
        "imageId": {"value": val("CUSTOM_IMAGE_ID")},
        "bootMode": {"value": val("BOOT_MODE")},
    })
else:
    params.update({
        "softwareVersion": {"value": val("SOFTWARE_VERSION")},
        "enableSecureBoot": {"value": val("ENABLE_SECURE_BOOT")},
        "ftdLicensingSku": {"value": val("FTD_LICENSING_SKU")},
    })

payload = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
    "contentVersion": "1.0.0.0",
    "parameters": params,
}
with open(os.environ["PARAMS_FILE"], "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2)
    handle.write("\n")
PY
}

render_logic_app() {
  SUBSCRIPTION_ID="${SUBSCRIPTION_ID}" RG="${RG}" PREFIX="${PREFIX}" LOCATION="${LOCATION}" LOGIC_BODY_FILE="${LOGIC_BODY_FILE}" AZURE_DIR="${AZURE_DIR}" python3 - <<'PY'
import json
import os

logic_path = os.path.join(os.environ["AZURE_DIR"], "target", "logic_app.txt")
with open(logic_path, encoding="utf-8") as handle:
    text = handle.read()

function_app_name = f"{os.environ['PREFIX']}-function-app"
text = text.replace("SUBSCRIPTION_ID", os.environ["SUBSCRIPTION_ID"])
text = text.replace("RESOURCE_GROUP_NAME", os.environ["RG"])
text = text.replace("FUNCTION_APP_NAME", function_app_name)
logic = json.loads(text)
body = {
    "location": os.environ["LOCATION"],
    "properties": {
        "definition": logic["definition"],
        "parameters": logic.get("parameters", {}),
        "state": "Enabled" if os.environ.get("ENABLE_LOGIC_APP") == "true" else "Disabled",
    },
}
with open(os.environ["LOGIC_BODY_FILE"], "w", encoding="utf-8") as handle:
    json.dump(body, handle, indent=2)
    handle.write("\n")
PY
}

build_function_package() {
  local build_dir
  build_dir="$(mktemp -d)"
  rm -f "${FUNCTION_PACKAGE_FILE}"

  rsync -a \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    --exclude '.python_packages' \
    "${AZURE_DIR}/function-app/" "${build_dir}/"

  python3 -m pip install \
    --only-binary=:all: \
    --platform "${FUNCTION_PACKAGE_BUILD_PLATFORM}" \
    --implementation cp \
    --python-version "${FUNCTION_PACKAGE_PYTHON_VERSION}" \
    --abi "${FUNCTION_PACKAGE_ABI}" \
    --target "${build_dir}/.python_packages/lib/site-packages" \
    -r "${AZURE_DIR}/function-app/requirements.txt" \
    --upgrade

  mkdir -p "$(dirname "${FUNCTION_PACKAGE_FILE}")"
  (cd "${build_dir}" && zip -qr "${FUNCTION_PACKAGE_FILE}" .)
  rm -rf "${build_dir}"

  FUNCTION_PACKAGE_FILE="${FUNCTION_PACKAGE_FILE}" python3 - <<'PY'
import os
import sys
import zipfile

package = os.environ["FUNCTION_PACKAGE_FILE"]
required = (
    "host.json",
    "SharedCode/Utils.py",
    ".python_packages/lib/site-packages/requests/__init__.py",
    ".python_packages/lib/site-packages/azure/identity/__init__.py",
)
with zipfile.ZipFile(package) as archive:
    names = set(archive.namelist())
    missing = [name for name in required if name not in names]
    cffi_entries = [name for name in names if "_cffi_backend" in name]

if missing:
    print("Function package is missing required files: {}".format(", ".join(missing)), file=sys.stderr)
    sys.exit(1)
if not cffi_entries:
    print("Function package is missing Linux _cffi_backend dependency", file=sys.stderr)
    sys.exit(1)
PY
}

echo "Cleaning old FMC devices for prefix ${PREFIX}"
cleanup_fmc_devices

if [[ -z "${CUSTOM_IMAGE_ID}" ]]; then
  echo "Accepting FTDv marketplace terms"
  if [[ "${SOFTWARE_VERSION}" == "10.00.140" ]]; then
    FTD_MARKETPLACE_PLAN="${FTD_MARKETPLACE_PLAN:-cisco-ftdv-x86-payg}"
  else
    FTD_MARKETPLACE_PLAN="${FTD_MARKETPLACE_PLAN:-${FTD_LICENSING_SKU}}"
  fi
  az vm image terms accept \
    --publisher cisco \
    --offer cisco-ftdv \
    --plan "${FTD_MARKETPLACE_PLAN}" \
    >/dev/null
else
  echo "Using custom image ${CUSTOM_IMAGE_ID}"
fi

echo "Building Azure function package"
python3 "${AZURE_DIR}/make.py" build
build_function_package

echo "Rendering parameters to ${PARAMS_FILE}"
render_parameters

if [[ -n "${CUSTOM_IMAGE_ID}" ]]; then
  TEMPLATE_FILE="${AZURE_DIR}/target/arm-templates/azure_ftdv_gwlb_autoscale_custom_image.json"
else
  TEMPLATE_FILE="${AZURE_DIR}/target/arm-templates/azure_ftdv_gwlb_autoscale.json"
fi
FUNCTION_APP_NAME="${PREFIX}-function-app"
LOGIC_APP_NAME="${PREFIX}-logic-app"
VMSS_NAME="${PREFIX}-vmss"

echo "Validating ARM template"
az deployment group validate \
  --resource-group "${RG}" \
  --template-file "${TEMPLATE_FILE}" \
  --parameters @"${PARAMS_FILE}" \
  --query properties.provisioningState \
  -o tsv

echo "Deploying ARM template"
az deployment group create \
  --resource-group "${RG}" \
  --name "${PREFIX}-gwlb-autoscale-$(date +%Y%m%d%H%M%S)" \
  --template-file "${TEMPLATE_FILE}" \
  --parameters @"${PARAMS_FILE}"

echo "Preparing Function App for package mount"
az rest \
  --method put \
  --uri "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RG}/providers/Microsoft.Web/sites/${FUNCTION_APP_NAME}/basicPublishingCredentialsPolicies/scm?api-version=2022-03-01" \
  --body '{"properties":{"allow":true}}' \
  >/dev/null
if [[ "${FUNCTION_HOSTING_PLAN}" == "premium" ]]; then
  az functionapp config set \
    --resource-group "${RG}" \
    --name "${FUNCTION_APP_NAME}" \
    --always-on true \
    --vnet-route-all-enabled true \
    >/dev/null
fi

validate_function_package() {
  FUNCTION_APP_NAME="${FUNCTION_APP_NAME}" python3 - <<'PY'
import os
import sys
import requests

function_app = os.environ["FUNCTION_APP_NAME"]
base_url = f"https://{function_app}.azurewebsites.net/api"
probes = [
    ("MinimumConfigVerification", {}),
    ("AutoScaleManager", {}),
    (
        "WaitForFtdToComeUp",
        {"ftdDevName": "validation", "ftdPublicIp": "127.0.0.1", "ftdPrivateIp": ""},
    ),
]

failed = []
for function_name, payload in probes:
    try:
        response = requests.post(f"{base_url}/{function_name}", json=payload, timeout=45)
    except Exception as exc:
        failed.append(f"{function_name}: {type(exc).__name__}: {exc}")
        continue

    if response.status_code == 404:
        failed.append(f"{function_name}: HTTP 404")
    elif response.status_code >= 500:
        failed.append(f"{function_name}: HTTP {response.status_code}: {response.text[:200]}")

if failed:
    print("\n".join(failed))
    sys.exit(1)
PY
}

echo "Uploading Azure function package"
STORAGE_ACCOUNT="$(az storage account list --resource-group "${RG}" --query "[?starts_with(name, '${PREFIX}')].name | [0]" -o tsv)"
STORAGE_KEY="$(az storage account keys list --resource-group "${RG}" --account-name "${STORAGE_ACCOUNT}" --query '[0].value' -o tsv)"
PACKAGE_CONTAINER="${PACKAGE_CONTAINER:-deployments}"
PACKAGE_BLOB="autoscale-function-$(date +%Y%m%d%H%M%S).zip"
az storage container create \
  --account-name "${STORAGE_ACCOUNT}" \
  --account-key "${STORAGE_KEY}" \
  --name "${PACKAGE_CONTAINER}" \
  --auth-mode key \
  >/dev/null
az storage blob upload \
  --account-name "${STORAGE_ACCOUNT}" \
  --account-key "${STORAGE_KEY}" \
  --container-name "${PACKAGE_CONTAINER}" \
  --name "${PACKAGE_BLOB}" \
  --file "${FUNCTION_PACKAGE_FILE}" \
  --overwrite true \
  --auth-mode key \
  >/dev/null
PACKAGE_EXPIRY="$(python3 - <<'PY'
from datetime import datetime, timedelta, timezone

print((datetime.now(timezone.utc) + timedelta(days=7)).strftime("%Y-%m-%dT%H:%MZ"))
PY
)"
PACKAGE_SAS="$(az storage blob generate-sas \
  --account-name "${STORAGE_ACCOUNT}" \
  --account-key "${STORAGE_KEY}" \
  --container-name "${PACKAGE_CONTAINER}" \
  --name "${PACKAGE_BLOB}" \
  --permissions r \
  --expiry "${PACKAGE_EXPIRY}" \
  -o tsv)"
PACKAGE_URL="https://${STORAGE_ACCOUNT}.blob.core.windows.net/${PACKAGE_CONTAINER}/${PACKAGE_BLOB}?${PACKAGE_SAS}"

echo "Mounting Azure function package"
az functionapp config appsettings set \
  --resource-group "${RG}" \
  --name "${FUNCTION_APP_NAME}" \
  --settings \
    WEBSITE_RUN_FROM_PACKAGE="${PACKAGE_URL}" \
    SCM_DO_BUILD_DURING_DEPLOYMENT=false \
    ENABLE_ORYX_BUILD=false \
  >/dev/null
az functionapp restart \
  --resource-group "${RG}" \
  --name "${FUNCTION_APP_NAME}"

echo "Waiting for functions to index"
indexed_functions=0
for attempt in $(seq 1 12); do
  if validate_function_package; then
    echo "Function package endpoint validation succeeded"
    indexed_functions=1
    break
  fi
  function_count="$(az functionapp function list --resource-group "${RG}" --name "${FUNCTION_APP_NAME}" --query 'length(@)' -o tsv 2>/dev/null || echo 0)"
  if [[ "${function_count}" == "18" ]]; then
    echo "Function validation attempt ${attempt}/12: ${function_count} indexed functions; endpoint probe still warming"
  else
    echo "Function validation attempt ${attempt}/12: ${function_count} indexed functions"
  fi
  sleep 20
done

if [[ "${indexed_functions}" != "1" ]]; then
  echo "Function package did not expose required functions. Leaving Logic App and VMSS unchanged." >&2
  exit 1
fi

echo "Syncing function triggers"
az rest \
  --method post \
  --uri "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RG}/providers/Microsoft.Web/sites/${FUNCTION_APP_NAME}/syncfunctiontriggers?api-version=2022-03-01" \
  >/dev/null || true

echo "Rendering and applying Logic App definition"
render_logic_app
az rest \
  --method put \
  --uri "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RG}/providers/Microsoft.Logic/workflows/${LOGIC_APP_NAME}?api-version=2019-05-01" \
  --body @"${LOGIC_BODY_FILE}" \
  >/dev/null
logic_action_count="$(az logic workflow show --resource-group "${RG}" --name "${LOGIC_APP_NAME}" --query 'length(definition.actions)' -o tsv)"
if [[ "${logic_action_count}" -lt 5 ]]; then
  echo "Logic App definition is incomplete: expected at least 5 actions, found ${logic_action_count}." >&2
  exit 1
fi

if [[ "${ENABLE_LOGIC_APP}" == "true" ]]; then
  echo "Enabling Logic App"
  az logic workflow update \
    --resource-group "${RG}" \
    --name "${LOGIC_APP_NAME}" \
    --state Enabled \
    >/dev/null
fi

if [[ "${SCALE_VMSS}" == "true" && "${ENABLE_LOGIC_APP}" == "true" ]]; then
  echo "Skipping direct VMSS scale because Logic App is enabled; AutoScaleManager will perform initial scale-out"
elif [[ "${SCALE_VMSS}" == "true" ]]; then
  echo "Scaling ${VMSS_NAME} to ${FTD_COUNT}"
  az vmss scale \
    --resource-group "${RG}" \
    --name "${VMSS_NAME}" \
    --new-capacity "${FTD_COUNT}" \
    >/dev/null
fi

echo "Deployment complete"
echo "Function App: ${FUNCTION_APP_NAME}"
echo "Logic App: ${LOGIC_APP_NAME}"
echo "VMSS: ${VMSS_NAME}"
echo "Parameter file: ${PARAMS_FILE}"
