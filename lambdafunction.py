import boto3
import time
import concurrent.futures

def create_and_run_reachability_analyzer(source_arn, destination_arn):
    client = boto3.client('ec2')

    try:
        # Create a Network Insights Path
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
                    print(f"Path from {source_arn} to {destination_arn} is not reachable")
            else:
                print(f"Analysis completed but 'NetworkPathFound' key not found in the response for path from {source_arn} to {destination_arn}")
        else:
            print(f"Analysis failed with status: {status} for path from {source_arn} to {destination_arn}")
    
    except Exception as e:
        print(f"An error occurred for path from {source_arn} to {destination_arn}: {e}")

def lambda_handler(event, context):
    arn_pairs = event.get('arn_pairs', [])
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(create_and_run_reachability_analyzer, source_arn, destination_arn) for source_arn, destination_arn in arn_pairs]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()  # This will re-raise any exceptions caught in the worker threads
            except Exception as e:
                print(f"An exception occurred: {e}")

