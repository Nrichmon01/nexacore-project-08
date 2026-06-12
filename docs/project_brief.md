# Project Brief — CloudTrail Log Analysis & Threat Detection
**Company:** NexaCore Technologies — Security Operations  
**Assigned By:** Daniel Osei-Mensah (Head of Cloud Infrastructure & Security)  
**Reported By:** Kwame Asante (Internal Security Auditor)  
**Environment:** AWS CloudTrail · Athena · GuardDuty · S3 · Lambda | eu-west-1  
**Urgency:** Critical — Suspected account compromise in progress  
**Duration:** 6 Days  

---

## Background
At 02:14 UTC on a Tuesday morning, NexaCore's billing alarm fires: unexpected EC2 instances were launched in a region NexaCore has never used (ap-southeast-1 — Singapore). Kwame, who is on-call, suspects either a compromised IAM credential or a misconfigured role. He needs to immediately investigate what happened, who did it, and from where — then build a system to catch this kind of activity automatically in the future.

CloudTrail has been logging for 90 days across all regions to an S3 bucket. GuardDuty is enabled but its findings have never been reviewed or acted upon. The job has two parts: investigate the current incident using CloudTrail + Athena, then build an automated threat detection and response workflow.

---

## Problem Statement
At 02:14 UTC, 6 EC2 instances (c5.4xlarge — expensive GPU-capable machines) were launched in ap-southeast-1 by an unknown actor. The billing impact was already $340 in 3 hours. GuardDuty had a finding: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`. The compromised credential belonged to `ops-user-2`. Investigate the full attack chain, contain the damage immediately, and build automated detection for future incidents.

---

## Infrastructure
- **CloudTrail:** multi-region trail logging to S3 bucket `nexacore-cloudtrail-logs` — 90 days of logs
- **GuardDuty:** enabled in eu-west-1 — unreviewed findings in the console
- **Athena:** database `nexacore_cloudtrail_db` configured
- **ops-user-2:** IAM user with ops permissions — credentials possibly leaked via a public GitHub repo
- **6 unauthorized c5.4xlarge instances** running in ap-southeast-1 — likely cryptomining
- **SNS topic:** `nexacore-security-alerts`
- **Lambda execution role** with EC2, IAM, and SNS permissions

---

## Steps to Solve
1. Disable `ops-user-2` IAM user and rotate all access keys to stop ongoing unauthorized access
2. Terminate all unauthorized EC2 instances in ap-southeast-1 using AWS CLI
3. Create an Athena table on top of the CloudTrail S3 bucket
4. Query Athena to find all API calls made by `ops-user-2` in the past 7 days
5. Query Athena to identify all EC2 RunInstances calls across all regions in the past 48 hours
6. Review all GuardDuty findings — classify as True Positive, False Positive, or Needs Investigation
7. Write a Python boto3 script that automatically disables an IAM user when a high-severity GuardDuty finding references their credentials
8. Create an EventBridge rule: trigger the Lambda when GuardDuty finding severity >= 7
9. Configure GuardDuty to export findings to an S3 bucket for long-term retention
10. Write an incident report documenting the attack chain, timeline, blast radius, and remediation steps

---

## Tools & Technologies
AWS CloudTrail · Amazon Athena · Amazon GuardDuty · AWS Lambda · EventBridge · IAM · Python boto3 · Amazon S3 · SNS · AWS CLI

---

## Expected Outcome
Incident contained within 25 minutes of investigation start. Full attack chain documented: credential leaked via GitHub → attacker used known Tor exit node → launched 6 cryptomining instances. Automated response system deployed: future GuardDuty high-severity findings trigger automatic user disablement and SNS alert within 60 seconds. Incident report submitted to management as per SLA.