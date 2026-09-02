import json
import boto3

s3_client = boto3.client('s3')

ALLOWED_PAIRS = {
    ("Corporate-IT", "Grid-Monitoring-Gateway"),
    ("Grid-Monitoring-Gateway", "Grid-Infrastructure"),
    ("Remote-VPN", "Grid-Infrastructure"),
    ("Corporate-IT", "Corporate-IT"),
}

def lambda_handler(event, context):
    bucket_name = event['Records'][0]['s3']['bucket']['name']
    file_key = event['Records'][0]['s3']['object']['key']

    response = s3_client.get_object(Bucket=bucket_name, Key=file_key)
    log_entries = json.loads(response['Body'].read())

    violations = []
    for entry in log_entries:
        pair = (entry['source_zone'], entry['dest_zone'])
        if pair not in ALLOWED_PAIRS:
            violations.append(entry)

    result_key = file_key.replace('logs/', 'results/').replace('.json', '_violations.json')

    s3_client.put_object(
        Bucket=bucket_name,
        Key=result_key,
        Body=json.dumps(violations, indent=2),
        ContentType='application/json'
    )

    print(f"Processed {len(log_entries)} entries, found {len(violations)} violations")
    return {"statusCode": 200, "body": f"{len(violations)} violations found"}
