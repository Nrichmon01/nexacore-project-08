"""
Project 08 - NexaCore Technologies
Script: disable_user.py
Purpose: Immediate response - disable compromised IAM user ops-user-2
         and deactivate all access keys to stop unauthorized access
Author: Richmond Asamoah Nkrumah
Date: June 2026
"""

import boto3
import json
import os
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

USERNAME = os.getenv("IAM_USERNAME")
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN")
REGION = os.getenv("REGION")


def disable_user_access_keys(iam_client, username):
    """Deactivate all access keys for the compromised user."""
    print(f"[*] Fetching access keys for user: {username}")

    keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']

    if not keys:
        print(f"[!] No access keys found for {username}")
        return []

    disabled_keys = []
    for key in keys:
        key_id = key['AccessKeyId']
        iam_client.update_access_key(
            UserName=username,
            AccessKeyId=key_id,
            Status='Inactive'
        )
        print(f"[+] Deactivated access key: {key_id}")
        disabled_keys.append(key_id)

    return disabled_keys


def send_alert(sns_client, username, disabled_keys):
    """Send SNS alert notifying the security team."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    message = f"""
[SECURITY INCIDENT ALERT] - NexaCore Technologies
Timestamp: {timestamp}

IMMEDIATE ACTION TAKEN:
- Compromised IAM user '{username}' access keys have been deactivated
- Disabled keys: {', '.join(disabled_keys)}

INCIDENT SUMMARY:
- Unauthorized EC2 instances detected in ap-southeast-1
- Suspected credential leak via public GitHub repository
- Access key {disabled_keys[0] if disabled_keys else 'N/A'} used by attacker

NEXT STEPS:
1. Investigate CloudTrail logs via Athena
2. Terminate unauthorized EC2 instances
3. Review full blast radius
4. Submit incident report

Assigned To: Richmond Asamoah Nkrumah (Cloud Security Intern)
Supervisor: Daniel Osei-Mensah (Head of Cloud Infrastructure & Security)
    """

    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="[CRITICAL] Compromised IAM User Disabled - ops-user-2",
        Message=message
    )
    print(f"[+] Alert sent to security team via SNS")


def main():
    print("=" * 60)
    print("NexaCore Incident Response - Disable Compromised User")
    print("=" * 60)

    iam_client = boto3.client('iam', region_name=REGION)
    sns_client = boto3.client('sns', region_name=REGION)

    # Step 1: Disable all access keys
    disabled_keys = disable_user_access_keys(iam_client, USERNAME)

    # Step 2: Send alert
    if disabled_keys:
        send_alert(sns_client, USERNAME, disabled_keys)

    print("\n[✓] Immediate response complete.")
    print(f"[✓] User '{USERNAME}' access keys deactivated.")
    print("[✓] Security team notified via SNS.")
    print("=" * 60)


if __name__ == "__main__":
    main()