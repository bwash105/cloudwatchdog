import boto3
from moto import mock_aws
from unittest.mock import patch
from checks import run_all_checks, SEVERITY


@mock_aws
def test_run_all_checks_returns_correct_structure():
    session = boto3.Session(region_name="us-east-1")
    results = run_all_checks(session, verbose=False)
    assert isinstance(results, list)
    assert len(results) == 20
    for name, findings in results:
        assert isinstance(name, str)
        assert name.startswith("check_")
        assert isinstance(findings, list)


def test_severity_values():
    assert SEVERITY["CRITICAL"] == 4
    assert SEVERITY["HIGH"] == 3
    assert SEVERITY["MEDIUM"] == 2
    assert SEVERITY["LOW"] == 1


import json
from checks import (
    check_iam_admin_policy_users,
    check_iam_wildcard_trust,
    check_sg_all_traffic_open,
    check_public_ec2_in_public_subnet,
    check_cloudtrail_log_validation,
    check_guardduty_enabled,
    check_config_enabled,
    check_s3_access_logging,
)


# ── IAM: admin policy on user ────────────────────────────────────────────────

@mock_aws
def test_check_iam_admin_policy_users_clean():
    session = boto3.Session(region_name="us-east-1")
    findings = check_iam_admin_policy_users(session)
    assert findings == []


def test_check_iam_admin_policy_users_finds_direct_admin():
    # Patch the IAM client so list_attached_user_policies returns the exact
    # AWS-managed ARN. moto assigns a local account ARN on create_policy, which
    # would not match the exact-match check.
    from unittest.mock import MagicMock
    aws_admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    mock_iam = MagicMock()
    mock_iam.list_users.return_value = {"Users": [{"UserName": "baduser"}]}
    mock_iam.list_attached_user_policies.return_value = {
        "AttachedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": aws_admin_arn}]
    }
    mock_session = MagicMock()
    mock_session.client.return_value = mock_iam
    findings = check_iam_admin_policy_users(mock_session)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["check"] == "iam_admin_policy_on_user"
    assert "baduser" in findings[0]["resource"]


# ── IAM: wildcard trust policy ───────────────────────────────────────────────

@mock_aws
def test_check_iam_wildcard_trust_clean():
    iam = boto3.client("iam", region_name="us-east-1")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
    })
    iam.create_role(RoleName="safe-role", AssumeRolePolicyDocument=trust)
    session = boto3.Session(region_name="us-east-1")
    findings = check_iam_wildcard_trust(session)
    assert findings == []


@mock_aws
def test_check_iam_wildcard_trust_finds_wildcard():
    iam = boto3.client("iam", region_name="us-east-1")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
    })
    iam.create_role(RoleName="dangerous-role", AssumeRolePolicyDocument=trust)
    session = boto3.Session(region_name="us-east-1")
    findings = check_iam_wildcard_trust(session)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["check"] == "iam_wildcard_trust_policy"


# ── Network: all-traffic SG ───────────────────────────────────────────────────

@mock_aws
def test_check_sg_all_traffic_open_clean():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.create_security_group(GroupName="safe-sg", Description="safe")
    session = boto3.Session(region_name="us-east-1")
    findings = check_sg_all_traffic_open(session)
    assert findings == []


@mock_aws
def test_check_sg_all_traffic_open_finds_wildcard_protocol():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="open-sg", Description="open")
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    session = boto3.Session(region_name="us-east-1")
    findings = check_sg_all_traffic_open(session)
    assert len(findings) >= 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["check"] == "sg_all_traffic_open"


@mock_aws
def test_check_sg_all_traffic_open_finds_ipv6_wildcard():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="ipv6-open-sg", Description="ipv6 open")
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}],
    )
    session = boto3.Session(region_name="us-east-1")
    findings = check_sg_all_traffic_open(session)
    assert any(f["check"] == "sg_all_traffic_open" and sg_id in f["resource"] for f in findings)


# ── Network: public EC2 in public subnet ─────────────────────────────────────

@mock_aws
def test_check_public_ec2_in_public_subnet_clean():
    session = boto3.Session(region_name="us-east-1")
    findings = check_public_ec2_in_public_subnet(session)
    assert findings == []


@mock_aws
def test_check_public_ec2_in_public_subnet_finds_exposed_instance():
    ec2 = boto3.client("ec2", region_name="us-east-1")

    # Create VPC + IGW + public subnet
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]
    igw = ec2.create_internet_gateway()
    igw_id = igw["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")
    subnet_id = subnet["Subnet"]["SubnetId"]

    rt = ec2.create_route_table(VpcId=vpc_id)
    rt_id = rt["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)

    # Launch instance with public IP in public subnet
    # Note: SubnetId must not be specified at the top level when NetworkInterfaces is used
    ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        NetworkInterfaces=[{
            "DeviceIndex": 0,
            "SubnetId": subnet_id,
            "AssociatePublicIpAddress": True,
        }],
    )

    session = boto3.Session(region_name="us-east-1")
    findings = check_public_ec2_in_public_subnet(session)
    assert len(findings) >= 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["check"] == "public_ec2_in_public_subnet"


# ── IR: CloudTrail log validation ────────────────────────────────────────────

@mock_aws
def test_check_cloudtrail_log_validation_clean():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="trail-bucket")
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    ct.create_trail(
        Name="my-trail",
        S3BucketName="trail-bucket",
        EnableLogFileValidation=True,
    )
    session = boto3.Session(region_name="us-east-1")
    findings = check_cloudtrail_log_validation(session)
    assert findings == []


@mock_aws
def test_check_cloudtrail_log_validation_finds_disabled_validation():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="trail-bucket")
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    ct.create_trail(
        Name="my-trail",
        S3BucketName="trail-bucket",
        EnableLogFileValidation=False,
    )
    session = boto3.Session(region_name="us-east-1")
    findings = check_cloudtrail_log_validation(session)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["check"] == "cloudtrail_log_validation_disabled"


# ── IR: GuardDuty enabled ────────────────────────────────────────────────────

@mock_aws
def test_check_guardduty_enabled_clean():
    gd = boto3.client("guardduty", region_name="us-east-1")
    gd.create_detector(Enable=True)
    session = boto3.Session(region_name="us-east-1")
    findings = check_guardduty_enabled(session)
    assert findings == []


@mock_aws
def test_check_guardduty_enabled_finds_no_detector():
    session = boto3.Session(region_name="us-east-1")
    findings = check_guardduty_enabled(session)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["check"] == "guardduty_not_enabled"


# ── Compliance: AWS Config ────────────────────────────────────────────────────

@mock_aws
def test_check_config_enabled_clean():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="config-logs-bucket")
    cfg = boto3.client("config", region_name="us-east-1")
    cfg.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": "arn:aws:iam::123456789012:role/config-role",
        }
    )
    # moto requires a delivery channel before start_configuration_recorder
    cfg.put_delivery_channel(
        DeliveryChannel={"name": "default", "s3BucketName": "config-logs-bucket"}
    )
    cfg.start_configuration_recorder(ConfigurationRecorderName="default")
    session = boto3.Session(region_name="us-east-1")
    findings = check_config_enabled(session)
    assert findings == []


@mock_aws
def test_check_config_enabled_finds_no_recorder():
    session = boto3.Session(region_name="us-east-1")
    findings = check_config_enabled(session)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["check"] == "config_not_enabled"


# ── Compliance: S3 access logging ────────────────────────────────────────────

@mock_aws
def test_check_s3_access_logging_clean():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="logged-bucket")
    s3.create_bucket(Bucket="log-dest-bucket")
    # moto requires the log-delivery group to have WRITE+READ_ACP on the target bucket
    s3.put_bucket_acl(
        Bucket="log-dest-bucket",
        GrantWrite="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
        GrantReadACP="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
    )
    s3.put_bucket_logging(
        Bucket="logged-bucket",
        BucketLoggingStatus={
            "LoggingEnabled": {"TargetBucket": "log-dest-bucket", "TargetPrefix": "logs/"}
        },
    )
    session = boto3.Session(region_name="us-east-1")
    findings = check_s3_access_logging(session)
    assert all(f["resource"] != "s3://logged-bucket" for f in findings)


@mock_aws
def test_check_s3_access_logging_finds_unlogged_bucket():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="silent-bucket")
    session = boto3.Session(region_name="us-east-1")
    findings = check_s3_access_logging(session)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["check"] == "s3_access_logging_disabled"
    assert findings[0]["resource"] == "s3://silent-bucket"


# ── Integration: full pipeline ──────────────────────────────────────────────────

from compliance import compute_compliance


@mock_aws
def test_full_pipeline_produces_valid_compliance_scores():
    """run_all_checks → compute_compliance → valid score structure."""
    session = boto3.Session(region_name="us-east-1")
    check_results = run_all_checks(session, verbose=False)
    scores = compute_compliance(check_results)

    assert "cis_aws_v2" in scores
    assert "nist_csf_coverage" in scores
    cis = scores["cis_aws_v2"]
    assert 0 <= cis["score_pct"] <= 100
    assert cis["total"] == 20

    nist = scores["nist_csf_coverage"]
    for fn in ["identify", "protect", "detect"]:
        assert isinstance(nist[fn], dict)
        assert "passing" in nist[fn]
        assert "total" in nist[fn]


@mock_aws
def test_check_open_ssh_rdp_finds_ipv6_ssh():
    from checks import check_open_ssh_rdp
    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="ipv6-ssh-sg", Description="ipv6 ssh")
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        }],
    )
    session = boto3.Session(region_name="us-east-1")
    findings = check_open_ssh_rdp(session)
    assert any(f["check"] == "open_ssh_rdp_to_world" and sg_id in f["resource"] for f in findings)


@mock_aws
def test_check_iam_user_mfa_clean():
    session = boto3.Session(region_name="us-east-1")
    from checks import check_iam_user_mfa
    # No users = no findings
    findings = check_iam_user_mfa(session)
    assert findings == []
