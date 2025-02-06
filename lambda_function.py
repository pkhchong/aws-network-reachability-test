import boto3
import json
import time
import concurrent.futures
import re

sts_client = boto3.client('sts')

def assume_role(account_id):
    """Assume the cross-account role and return session credentials."""
    role_arn = f"arn:aws:iam::{account_id}:role/ReachabilityTest"
    try:
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="CrossAccountSession"
        )
        print(f"Assumed role successfully for account {account_id}.")
        return assumed_role['Credentials']
    except Exception as e:
        print(f"Failed to assume role for account {account_id}: {e}")
        raise

def get_instance_arn_by_tag(account_id, region, tag_key, tag_value):
    """Retrieve the instance ARN for a given tag key and value."""
    creds = assume_role(account_id)
    ec2_client = boto3.client(
        'ec2',
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
        region_name=region
    )
    response = ec2_client.describe_instances(
        Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}]
    )
    instances = response['Reservations']
    if instances:
        instance_id = instances[0]['Instances'][0]['InstanceId']
        return f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
    return None

def create_and_run_reachability_analyzer(account_id, source_arn, destination_arn):
    """Perform a reachability test between two ARNs, resolving tags if necessary."""
    creds = assume_role(account_id)
    ec2_client = boto3.client(
        'ec2',
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken']
    )
    not_reachable_message = ""

    try:
        # Resolve tags to ARNs if necessary
        if 'instance_tag_' in source_arn and '%%%' in source_arn:
            tag_key, tag_value = source_arn.split('instance_tag_')[1].split('%%%')
            source_arn = get_instance_arn_by_tag(account_id, 'ap-east-1', tag_key, tag_value)

        if 'instance_tag_' in destination_arn and '%%%' in destination_arn:
            tag_key, tag_value = destination_arn.split('instance_tag_')[1].split('%%%')
            destination_arn = get_instance_arn_by_tag(account_id, 'ap-east-1', tag_key, tag_value)

        if not source_arn or not destination_arn:
            return f"Unable to resolve ARNs for source or destination: {source_arn}, {destination_arn}"

        # Debugging: Print parameters used for the analysis
        print(f"Debug: Attempting to create a Network Insights Path with parameters:")
        print(f"  Source ARN: {source_arn}")
        print(f"  Destination ARN: {destination_arn}")
        print(f"  Protocol: tcp")
        print(f"  Destination Port: 80")

        # Regular expression to match IPv4 addresses
        ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
        
        if ip_pattern.match(destination_arn):
            # If destination_arn is an IP address
            response = ec2_client.create_network_insights_path(
                Source=source_arn,
                FilterAtSource={'DestinationAddress': destination_arn},
                Protocol='tcp'  # You can specify the protocol (tcp, udp, icmp, etc.)
            )
        else:
            # If destination_arn is not an IP address
            response = ec2_client.create_network_insights_path(
                Source=source_arn,
                Destination=destination_arn,
                Protocol='tcp',  # You can specify the protocol (tcp, udp, icmp, etc.)
                DestinationPort=80  # You can specify the port
            )
        path_id = response['NetworkInsightsPath']['NetworkInsightsPathId']
        print(f"Created Network Insights Path with ID: {path_id}")

        # Start the Reachability Analysis
        analysis_response = ec2_client.start_network_insights_analysis(
            NetworkInsightsPathId=path_id
        )
        analysis_id = analysis_response['NetworkInsightsAnalysis']['NetworkInsightsAnalysisId']
        print(f"Started Network Insights Analysis with ID: {analysis_id}")

        # Wait for the analysis to complete
        while True:
            analysis_result = ec2_client.describe_network_insights_analyses(
                NetworkInsightsAnalysisIds=[analysis_id]
            )
            status = analysis_result['NetworkInsightsAnalyses'][0]['Status']
            if status == 'running':
                print(f"Analysis {analysis_id} is running, waiting for it to complete...")
                time.sleep(10)
            else:
                break

        # Check the analysis result
        if status == 'succeeded':
            analysis = analysis_result['NetworkInsightsAnalyses'][0]
            if 'NetworkPathFound' in analysis:
                path_found = analysis['NetworkPathFound']
                if path_found:
                    print(f"Path from {source_arn} to {destination_arn} is reachable")
                else:
                    not_reachable_message = f"Path from {source_arn} to {destination_arn} is not reachable"
                    print(not_reachable_message)
            else:
                print(f"Analysis completed but 'NetworkPathFound' key not found in the response for path from {source_arn} to {destination_arn}")
        else:
            print(f"Analysis failed with status: {status} for path from {source_arn} to {destination_arn}")
    except Exception as e:
        # Debugging: Print detailed error information
        print(f"An error occurred for path from {source_arn} to {destination_arn}: {e}")
        print(f"Debug: Error details - account_id: {account_id}, source_arn: {source_arn}, destination_arn: {destination_arn}")
        not_reachable_message = f"Error for path from {source_arn} to {destination_arn}: {str(e)}"

    return not_reachable_message

def send_alert(message, sns_topic_arn, account_id, region):
    """Send an alert via SNS using the assumed role's credentials."""
    creds = assume_role(account_id)
    sns_client = boto3.client(
        'sns',
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
        region_name=region
    )
    try:
        print(f"Attempting to publish to SNS topic {sns_topic_arn} with assumed role.")
        response = sns_client.publish(
            TopicArn=sns_topic_arn,
            Message=message,
            Subject='Network Path Reachability Alert'
        )
        print(f"Alert sent successfully. Message ID: {response['MessageId']}")
    except Exception as e:
        print(f"Failed to send alert using assumed role for account {account_id}: {e}")

def lambda_handler(event, context):
    """Main handler for cross-account reachability test."""
    file_path = './event.json'
    with open(file_path, 'r') as file:
        event_data = json.load(file)

    for account in event_data['accounts']:
        account_id = account['AccountId']
        sns_topic_arn = account['sns_topic_arn']
        arn_pairs = account['arn_pairs']
        not_reachable_messages = []

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [
                executor.submit(create_and_run_reachability_analyzer, account_id, source_arn, destination_arn)
                for source_arn, destination_arn in arn_pairs
            ]

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    not_reachable_messages.append(result)

        if not_reachable_messages:
            alert_message = '\n'.join(not_reachable_messages)
            send_alert(alert_message, sns_topic_arn, account_id, 'ap-east-1')
