# Incident Report 001 — NexaCore Technologies
**Project:** Project 08 — Automated GuardDuty Incident Response  
**Author:** Richmond Asamoah Nkrumah  
**Date:** June 12, 2026  
**Severity:** High (8/10)  
**Status:** Resolved  

---

## 1. Incident Summary
A high-severity GuardDuty finding of type `UnauthorizedAccess:IAMUser/MaliciousIPCaller` was detected against IAM user `ops-user-2` in account `496411573400` (eu-west-1). The automated response system successfully disabled the compromised user and notified the security team within seconds.

---

## 2. Timeline
| Time (UTC) | Event |
|---|---|
| 2026-06-12 08:33:24 | GuardDuty finding detected — severity 8 |
| 2026-06-12 08:33:24 | EventBridge rule triggered Lambda function |
| 2026-06-12 08:33:24 | Lambda disabled ops-user-2 access keys |
| 2026-06-12 08:33:24 | SNS alert sent to security team email |

---

## 3. Affected Resources
- **IAM User:** ops-user-2
- **Access Key:** AKIAXHFDPPSMNTBNGFVV
- **Region:** eu-west-1
- **Account:** 496411573400

---

## 4. Root Cause
Access key belonging to `ops-user-2` was flagged for making API calls from a known malicious IP address, indicating potential credential compromise.

---

## 5. Automated Response Actions Taken
1. Lambda function `nexacore-guardduty-response` triggered by EventBridge
2. IAM user `ops-user-2` access keys deactivated via `iam:UpdateAccessKey`
3. SNS notification sent to security team via `nexacore-security-alerts` topic

---

## 6. Recommended Next Steps
1. Review CloudTrail logs via Athena for full attack chain
2. Check for any resources created by the compromised user
3. Rotate any secrets the user had access to
4. Submit findings to management within 24 hours
5. Consider enabling GuardDuty threat intelligence feeds

---

## 7. Lessons Learned
- Automated response reduced mean time to respond (MTTR) to under 5 seconds
- IAM users should follow least privilege — `ops-user-2` had `AmazonEC2FullAccess` which is broader than needed
- Access keys should be replaced with IAM roles where possible