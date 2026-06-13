"""
Project 08 - NexaCore Technologies
Script: lambda/guardduty_response.py
Purpose: Automated response to GuardDuty findings.
         Triggered by EventBridge when a high-severity finding is detected.
         Automatically disables the compromised IAM user and sends SNS alert.
Author: Richmond Asamoah Nkrumah
Date: June 2026
"""

import boto3
import json
import os
from datetime import datetime, timezone

# In Lambda, environment variables are set in the function configuration
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
REGION = os.environ.get("REGION", "eu-west-1")


def disable_user_access_keys(iam_client, username):
    """Deactivate all access keys for the compromised user."""
    print(f"[*] Disabling access keys for user: {username}")

    keys = iam_client.list_access_keys(
        UserName=username
    )['AccessKeyMetadata']

    disabled_keys = []
    for key in keys:
        key_id = key['AccessKeyId']
        if key['Status'] == 'Active':
            iam_client.update_access_key(
                UserName=username,
                AccessKeyId=key_id,
                Status='Inactive'
            )
            print(f"[+] Deactivated key: {key_id}")
            disabled_keys.append(key_id)

    return disabled_keys


def send_alert(sns_client, username, finding, disabled_keys):
    """Send SNS alert to security team."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    severity = finding.get('severity', 'Unknown')
    finding_type = finding.get('type', 'Unknown')
    description = finding.get('description', 'No description available')

    message = f"""
[AUTOMATED GUARDDUTY RESPONSE] - NexaCore Technologies
Timestamp: {timestamp}

GUARDDUTY FINDING:
- Finding Type: {finding_type}
- Severity: {severity}
- Description: {description}

AUTOMATED ACTION TAKEN:
- Compromised user '{username}' access keys deactivated
- Disabled keys: {', '.join(disabled_keys) if disabled_keys else 'None found'}

NEXT STEPS FOR SECURITY TEAM:
1. Review CloudTrail logs via Athena for full attack chain
2. Check for any resources created by compromised user
3. Rotate any secrets the user had access to
4. Submit incident report within 24 hours

This response was automated by the NexaCore GuardDuty Response System.
Assigned To: Richmond Asamoah Nkrumah (Cloud Security Intern)
Supervisor: Daniel Osei-Mensah (Head of Cloud Infrastructure & Security)
    """

    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[AUTOMATED] GuardDuty Finding - Severity {severity} - User {username} Disabled",
        Message=message
    )
    print(f"[+] Alert sent to security team via SNS")


def extract_username(event):
    """Extract compromised username from GuardDuty finding."""
    try:
        detail = event.get('detail', {})
        resource = detail.get('resource', {})
        access_key_details = resource.get('accessKeyDetails', {})
        username = access_key_details.get('userName', None)
        return username
    except Exception as e:
        print(f"[!] Could not extract username: {e}")
        return None


def lambda_handler(event, context):
    """
    Main Lambda handler - triggered by EventBridge GuardDuty finding.
    Event structure follows AWS GuardDuty finding format.
    """
    print("[*] GuardDuty Response Lambda triggered")
    print(f"[*] Event: {json.dumps(event, indent=2)}")

    iam_client = boto3.client('iam', region_name=REGION)
    sns_client = boto3.client('sns', region_name=REGION)

    # Extract finding details
    detail = event.get('detail', {})
    severity = detail.get('severity', 0)
    finding_type = detail.get('type', 'Unknown')

    print(f"[*] Finding type: {finding_type}")
    print(f"[*] Severity: {severity}")

    # Only respond to high severity findings (>= 7)
    if severity < 7:
        print(f"[!] Severity {severity} below threshold. No action taken.")
        return {
            'statusCode': 200,
            'body': f'Severity {severity} below threshold - no action taken'
        }

    # Extract compromised username
    username = extract_username(event)
    if not username:
        print("[!] Could not identify compromised user. Manual review required.")
        return {
            'statusCode': 400,
            'body': 'Could not identify compromised user'
        }

    print(f"[*] Compromised user identified: {username}")

    # Disable access keys
    disabled_keys = disable_user_access_keys(iam_client, username)

    # Send alert
    send_alert(sns_client, username, detail, disabled_keys)

    print(f"[✓] Automated response complete for user: {username}")

    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': f'Successfully disabled user {username}',
            'disabled_keys': disabled_keys,
            'severity': severity,
            'finding_type': finding_type
        })
    }