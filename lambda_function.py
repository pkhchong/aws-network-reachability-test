import boto3
import time
import concurrent.futures
import json
import re

sns_client = boto3.client('sns')

def get_instance_id_by_tag(tag_key, tag_value):
    ec2 = boto3.client('ec2')
    response = ec2.describe_instances(Filters=[
        {'Name': f'tag:{tag_key}', 'Values': [tag_value]}
    ])
    instances = response['Reservations']
    if instances:
        return instances[0]['Instances'][0]['InstanceId']
    else:
        return None

def create_and_run_reachability_analyzer(source_arn, destination_arn):
    client = boto3.client('ec2')
    not_reachable_message = ""

    try:
        # Check if source_arn and destination_arn contain the instance_tag keyword
        if 'instance_tag_' in source_arn and '%%%' in source_arn:
            tag_key, tag_value = source_arn.split('instance_tag_')[1].split('%%%')
            source_arn = get_instance_id_by_tag(tag_key, tag_value)
            if not source_arn:
                print(f"Failed to retrieve instance ID for source ARN: {source_arn}")
                return f"Failed to retrieve instance ID for source ARN: {source_arn}"
        
        if 'instance_tag_' in destination_arn and '%%%' in destination_arn:
            tag_key, tag_value = destination_arn.split('instance_tag_')[1].split('%%%')
            destination_arn = get_instance_id_by_tag(tag_key, tag_value)
            if not destination_arn:
                print(f"Failed to retrieve instance ID for destination ARN: {destination_arn}")
                return f"Failed to retrieve instance ID for destination ARN: {destination_arn}"

                # Regular expression to match IPv4 addresses
        ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
        
        if ip_pattern.match(destination_arn):
            # If destination_arn is an IP address
            response = client.create_network_insights_path(
                Source=source_arn,
                FilterAtSource={'DestinationAddress': destination_arn},
                Protocol='tcp'  # You can specify the protocol (tcp, udp, icmp, etc.)
            )
        else:
            # If destination_arn is not an IP address
            response = client.create_network_insights_path(
                Source=source_arn,
                Destination=destination_arn,
                Protocol='tcp',  # You can specify the protocol (tcp, udp, icmp, etc.)
                DestinationPort=80  # You can specify the port
            )
        
        path_id = response['NetworkInsightsPath']['NetworkInsightsPathId']
        print(f"Created Network Insights Path with ID: {path_id}")
        
        # Start the Reachability Analysis
        analysis_response = client.start_network_insights_analysis(
            NetworkInsightsPathId=path_id
        )
        
        analysis_id = analysis_response['NetworkInsightsAnalysis']['NetworkInsightsAnalysisId']
        print(f"Started Network Insights Analysis with ID: {analysis_id}")
        
        # Wait for the analysis to complete
        while True:
            analysis_result = client.describe_network_insights_analyses(
                NetworkInsightsAnalysisIds=[analysis_id]
            )
            status = analysis_result['NetworkInsightsAnalyses'][0]['Status']
            if status == 'running':
                print(f"Analysis {analysis_id} is running, waiting for it to complete...")
                time.sleep(10)  # Wait for 10 seconds before checking again
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
        print(f"An error occurred for path from {source_arn} to {destination_arn}: {e}")
    
    return not_reachable_message

def send_alert(message, sns_topic_arn):
    response = sns_client.publish(
        TopicArn=sns_topic_arn,
        Message=message,
        Subject='Network Path Reachability Alert'
    )
    print(f"Alert sent. Message ID: {response['MessageId']}")

def lambda_handler(event, context):
    # Read the JSON data from the file
    file_path = './event.json'  # Update with the correct file path
    with open(file_path, 'r') as file:
        data = json.load(file)
    
    arn_pairs = data.get('arn_pairs', [])
    sns_topic_arn = data.get('sns_topic_arn', '')
    not_reachable_messages = []

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(create_and_run_reachability_analyzer, source_arn, destination_arn) for source_arn, destination_arn in arn_pairs]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                not_reachable_message = future.result()  # This will re-raise any exceptions caught in the worker threads
                if not_reachable_message:
                    not_reachable_messages.append(not_reachable_message)
            except Exception as e:
                print(f"An exception occurred: {e}")
    
    if not_reachable_messages:
        message = '\n'.join(not_reachable_messages)
        send_alert(message, sns_topic_arn)
