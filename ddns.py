import requests
import ipaddress
from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.dnspod.v20210323 import dnspod_client, models
from datetime import datetime

# Configuration for region and keys
SECRET_ID = "[Your SECRET ID]"
SECRET_KEY = "Your SECRET KEY"
DOMAIN = "Your DOMAIN"

# Device configuration
DEVICES = {
    "DeviceA": {
        "sub_domain": "DeviceA",
        "ipv6_suffix": "[48bit ipv6 address tail]"
    },
    "DeviceB": {
        "sub_domain": "DeviceB",
        "ipv6_suffix": "[48bit ipv6 address tail]"
    },
    "DeviceC": {
        "sub_domain": "DeviceC",
        "ipv6_suffix": "[48bit ipv6 address tail]"
    }
    # More devices can be added here
}

def get_current_time():
    """Get the current time in a formatted string"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_public_ipv6():
    """Get the public IPv6 address of the machine"""
    try:
        headers = {"User-Agent": "curl/7.64.1"}
        response = requests.get("https://api6.ipify.org", headers=headers, timeout=10)
        response.raise_for_status()
        ip = response.text.strip()
        
        print(f"{get_current_time()} - Public IPv6 address obtained: {ip}")
        return ip
    except Exception as e:
        print(f"{get_current_time()} - Failed to get public IPv6 address: {e}")
        return None

def extract_ipv6_prefix(ipv6):
    """Extract the prefix part (first 64 bits) of an IPv6 address"""
    try:
        ip_obj = ipaddress.IPv6Address(ipv6)
        return str(ip_obj).rsplit(":", 4)[0]
    except ipaddress.AddressValueError:
        print(f"{get_current_time()} - Invalid IPv6 address: {ipv6}")
        return None

def update_dns_record(device_name, full_ipv6):
    """Update Tencent Cloud DNS record"""
    try:
        device = DEVICES[device_name]
        sub_domain = device["sub_domain"]

        # Initialize Tencent Cloud client
        cred = credential.Credential(SECRET_ID, SECRET_KEY)
        http_profile = HttpProfile()
        http_profile.endpoint = "dnspod.tencentcloudapi.com"
        client_profile = ClientProfile()
        client_profile.httpProfile = http_profile
        client = dnspod_client.DnspodClient(cred, "", client_profile)

        # Get domain record list
        describe_request = models.DescribeRecordListRequest()
        describe_request.Domain = DOMAIN
        describe_request.Subdomain = sub_domain
        describe_response = client.DescribeRecordList(describe_request)
        records = describe_response.RecordList

        # Find the matching record
        record_id = None
        for record in records:
            if record.Type == "AAAA" and record.Name == sub_domain:
                record_id = record.RecordId
                break

        if not record_id:
            print(f"{get_current_time()} - No matching DNS record found: {sub_domain}")
            return

        # Update the record
        modify_request = models.ModifyRecordRequest()
        modify_request.Domain = DOMAIN
        modify_request.RecordId = record_id
        modify_request.SubDomain = sub_domain
        modify_request.RecordType = "AAAA"
        modify_request.RecordLine = "默认"
        modify_request.Value = full_ipv6
        # print(f"Update request parameters: {modify_request.to_json_string()}")  # Debug output
        client.ModifyRecord(modify_request)
        print(f"{get_current_time()} - DNS record for device {device_name} has been updated to: {full_ipv6}")
    except Exception as e:
        print(f"{get_current_time()} - Failed to update DNS record for device {device_name}: {e}")

if __name__ == "__main__":
    public_ipv6 = get_public_ipv6()
    if public_ipv6:
        ipv6_prefix = extract_ipv6_prefix(public_ipv6)
        if ipv6_prefix:
            for device_name, config in DEVICES.items():
                try:
                    # Construct the full IPv6 address
                    full_ipv6 = f"{ipv6_prefix}:{config['ipv6_suffix']}"
                    update_dns_record(device_name, full_ipv6)
                except Exception as e:
                    print(f"{get_current_time()} - Failed to update device {device_name}: {e}")
            print(f"{get_current_time()} - All devices have been updated successfully.")
        else:
            print(f"{get_current_time()} - Failed to extract IPv6 address prefix")
    else:
        print(f"{get_current_time()} - Invalid public IPv6 address")
