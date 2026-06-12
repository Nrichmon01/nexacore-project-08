"""
Project 08 - NexaCore Technologies
Script: investigate_cloudtrail.py
Purpose: Query CloudTrail logs via Athena to investigate
         the attack chain from the compromised ops-user-2 account
Author: Richmond Asamoah Nkrumah
Date: June 2026
"""

import boto3
import os
import time
from dotenv import load_dotenv

load_dotenv()

REGION = os.getenv("REGION")
DATABASE = os.getenv("DATABASE")
TABLE = os.getenv("TABLE")
OUTPUT_BUCKET = os.getenv("OUTPUT_BUCKET")


def run_query(athena_client, query, description):
    """Execute an Athena query and wait for results."""
    print(f"\n[*] Running: {description}")
    print(f"[*] Query: {query[:80]}...")

    response = athena_client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={'Database': DATABASE},
        ResultConfiguration={'OutputLocation': OUTPUT_BUCKET}
    )

    query_id = response['QueryExecutionId']
    print(f"[*] Query ID: {query_id}")

    # Wait for query to complete
    while True:
        status = athena_client.get_query_execution(
            QueryExecutionId=query_id
        )['QueryExecution']['Status']['State']

        if status == 'SUCCEEDED':
            print(f"[+] Query succeeded")
            break
        elif status in ['FAILED', 'CANCELLED']:
            reason = athena_client.get_query_execution(
                QueryExecutionId=query_id
            )['QueryExecution']['Status']['StateChangeReason']
            print(f"[!] Query {status}: {reason}")
            return None
        else:
            print(f"[*] Status: {status}... waiting")
            time.sleep(3)

    # Get results
    results = athena_client.get_query_results(QueryExecutionId=query_id)
    return results


def print_results(results, title):
    """Print query results in a readable format."""
    if not results:
        print(f"[!] No results for: {title}")
        return

    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")

    rows = results['ResultSet']['Rows']
    if len(rows) <= 1:
        print("  No matching records found.")
        return

    # Print header
    headers = [col['VarCharValue'] for col in rows[0]['Data']]
    print("  " + " | ".join(headers))
    print("  " + "-" * 50)

    # Print data rows
    for row in rows[1:]:
        values = [col.get('VarCharValue', 'N/A') for col in row['Data']]
        print("  " + " | ".join(values))


def main():
    print("=" * 60)
    print("NexaCore Incident Investigation - CloudTrail Analysis")
    print("=" * 60)

    athena_client = boto3.client('athena', region_name=REGION)

    # Query 1: All access key and IAM activity (our incident response actions)
    query1 = f"""
    SELECT eventtime, eventname, awsregion, sourceipaddress, errorcode
    FROM {TABLE}
    WHERE eventsource = 'iam.amazonaws.com'
    ORDER BY eventtime DESC
    LIMIT 20
    """
    results1 = run_query(athena_client, query1,
                         "All API calls by ops-user-2")
    print_results(results1, "Activity by ops-user-2")

    # Query 2: EC2 instance launches across all regions
    query2 = f"""
    SELECT eventtime, awsregion, sourceipaddress, errorcode
    FROM {TABLE}
    WHERE eventname = 'RunInstances'
    ORDER BY eventtime DESC
    LIMIT 20
    """
    results2 = run_query(athena_client, query2,
                         "All EC2 RunInstances calls")
    print_results(results2, "EC2 Instance Launches")

    # Query 3: All activity grouped by region
    query3 = f"""
    SELECT awsregion, eventname, COUNT(*) as event_count
    FROM {TABLE}
    GROUP BY awsregion, eventname
    ORDER BY event_count DESC
    LIMIT 20
    """
    results3 = run_query(athena_client, query3,
                         "Activity by region for ops-user-2")
    print_results(results3, "Regional Activity Breakdown")

    print(f"\n[✓] Investigation queries complete.")
    print(f"[✓] Results saved to: {OUTPUT_BUCKET}")
    print("=" * 60)


if __name__ == "__main__":
    main()