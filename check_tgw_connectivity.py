import boto3
import time

def create_and_run_reachability_analyzer(source_arn, destination_arn):
    client = boto3.client('ec2')

    try:
        # Create a Reachability Analyzer Path
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
                print("Analysis is running, waiting for it to complete...")
                time.sleep(10)  # Wait for 10 seconds before checking again
            else:
                break
        
        # Check the analysis result
        if status == 'succeeded':
            # print(analysis_result)
            path_found = analysis_result['NetworkInsightsAnalyses'][0]['NetworkPathFound']
            if path_found:
                print("Path is reachable")
            else:
                print("Path is not reachable")
        else:
            print(f"Analysis failed with status: {status}")
    
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    source_arn = 'arn:aws:ec2:ap-east-1:424075490046:transit-gateway/tgw-0285f54acefc9a596'
    destination_arn = 'arn:aws:ec2:ap-east-1:424075490046:transit-gateway-attachment/tgw-attach-01dce24c9315fc3af'
    create_and_run_reachability_analyzer(source_arn, destination_arn)
