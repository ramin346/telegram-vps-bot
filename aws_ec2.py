"""Amazon EC2 API calls using the AWS SDK."""

from contextlib import closing, contextmanager
import re

INSTANCE_TYPES = ("t3.micro", "t3.small", "t3.medium", "t3.large", "t3a.micro", "t3a.small", "t3a.medium", "m6i.large")
ACTIONS = {
    "start": ("start_instances", "🟢 روشن کردن"),
    "stop": ("stop_instances", "🔴 خاموش کردن"),
    "reboot": ("reboot_instances", "🔄 راه‌اندازی مجدد"),
    "terminate": ("terminate_instances", "🗑 حذف دائمی"),
}


class APIError(Exception):
    pass


@contextmanager
def client(credentials, region):
    try:
        import boto3
        from botocore.config import Config
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        raise APIError("کتابخانهٔ boto3 روی میزبان ربات در دسترس نیست.") from None

    try:
        with closing(boto3.session.Session().client(
            "ec2", region_name=region, aws_access_key_id=credentials[0],
            aws_secret_access_key=credentials[1], aws_session_token=credentials[2] if len(credentials) == 3 else None,
            config=Config(connect_timeout=8, read_timeout=15,
                          retries={"mode": "standard", "total_max_attempts": 2}),
        )) as ec2:
            yield ec2
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        safe_code = code if re.fullmatch(r"[A-Za-z0-9._-]{1,100}", code) else "Unknown"
        raise APIError(f"AWS درخواست را نپذیرفت ({safe_code}).") from None
    except BotoCoreError:
        raise APIError("ارتباط با API سرویس AWS برقرار نشد.") from None


def regions(ec2):
    return sorted(row["RegionName"] for row in ec2.describe_regions()["Regions"])


def name(row):
    return next((tag["Value"] for tag in row.get("Tags", []) if tag["Key"] == "Name" and tag["Value"]),
                row["InstanceId"])


def instances(ec2):
    pages = ec2.get_paginator("describe_instances").paginate(Filters=[{
        "Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped", "shutting-down"],
    }])
    return sorted((row for page in pages for reservation in page["Reservations"] for row in reservation["Instances"]),
                  key=lambda row: (name(row), row["InstanceId"]))


def details(ec2, instance_id):
    data = ec2.describe_instances(InstanceIds=[instance_id])
    return next((row for reservation in data["Reservations"] for row in reservation["Instances"]), None)


def images(ec2):
    families = (
        ("Ubuntu 24.04 LTS", "099720109477", "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"),
        ("Ubuntu 22.04 LTS", "099720109477", "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"),
        ("Amazon Linux 2023", "amazon", "al2023-ami-2023.*-kernel-*-x86_64"),
    )
    choices = []
    for label, owner, pattern in families:
        images = ec2.describe_images(Owners=[owner], Filters=[
            {"Name": "name", "Values": [pattern]}, {"Name": "state", "Values": ["available"]},
            {"Name": "architecture", "Values": ["x86_64"]},
        ])["Images"]
        if images:
            latest = max(images, key=lambda row: row["CreationDate"])
            choices.append((latest["ImageId"], label))
    return choices


def subnets(ec2):
    pages = ec2.get_paginator("describe_subnets").paginate(Filters=[{"Name": "state", "Values": ["available"]}])
    return [(row["SubnetId"], f"{row['SubnetId']} · {row['AvailabilityZone']} · {row['VpcId']}")
            for page in pages for row in page["Subnets"]]


def types(ec2, subnet_id):
    zone = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]["AvailabilityZone"]
    pages = ec2.get_paginator("describe_instance_type_offerings").paginate(LocationType="availability-zone", Filters=[
        {"Name": "location", "Values": [zone]}, {"Name": "instance-type", "Values": list(INSTANCE_TYPES)},
    ])
    offered = {row["InstanceType"] for page in pages for row in page["InstanceTypeOfferings"]}
    return [(kind, kind) for kind in INSTANCE_TYPES if kind in offered]


def groups(ec2, subnet_id):
    vpc = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]["VpcId"]
    pages = ec2.get_paginator("describe_security_groups").paginate(Filters=[{"Name": "vpc-id", "Values": [vpc]}])
    return [(row["GroupId"], f"{row['GroupName']} · {row['GroupId']}")
            for page in pages for row in page["SecurityGroups"]]


def keys(ec2):
    return sorted((row["KeyName"], row["KeyName"]) for row in ec2.describe_key_pairs()["KeyPairs"])


def create(ec2, form, request_id):
    result = ec2.run_instances(
        ImageId=form["image"], InstanceType=form["type"], MinCount=1, MaxCount=1,
        ClientToken=request_id, KeyName=form["key"],
        NetworkInterfaces=[{
            "DeviceIndex": 0, "SubnetId": form["subnet"], "Groups": [form["group"]],
            "AssociatePublicIpAddress": True,
        }],
        MetadataOptions={"HttpTokens": "required"},
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": form["name"]}]}],
    )
    return result["Instances"][0]["InstanceId"]


def change(ec2, instance_id, action):
    method, _ = ACTIONS[action]
    getattr(ec2, method)(InstanceIds=[instance_id])


def call(credentials, region, action, *args):
    with client(credentials, region) as ec2:
        return action(ec2, *args)
