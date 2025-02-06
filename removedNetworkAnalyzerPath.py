import boto3

# List of AWS CLI profiles to use
profiles = ['cura-prod', 'hkgi-prod']

def delete_extra_network_insights_paths_for_client(ec2):
    """
    Deletes all network insights paths (except the first 50) for a given EC2 client.
    For each path to delete, it first deletes any associated analyses.
    """
    # Retrieve all Reachability Analyzer paths (NetworkInsightsPaths) using a paginator.
    all_paths = []
    paginator = ec2.get_paginator('describe_network_insights_paths')
    for page in paginator.paginate():
        paths = page.get('NetworkInsightsPaths', [])
        all_paths.extend(paths)

    total_paths = len(all_paths)
    print(f"Found {total_paths} network insights paths.")

    # Skip the first 50 paths; delete the remaining ones.
    paths_to_delete = all_paths[50:]
    if not paths_to_delete:
        print("Nothing to delete (fewer than or equal to 50 paths).")
        return

    for path in paths_to_delete:
        path_id = path.get('NetworkInsightsPathId')
        if not path_id:
            continue

        print(f"\nProcessing path: {path_id}")

        # Retrieve and delete any analyses for this path.
        analyses = []
        analyses_paginator = ec2.get_paginator('describe_network_insights_analyses')
        # Filter analyses by the specific path ID.
        for analysis_page in analyses_paginator.paginate(NetworkInsightsPathId=path_id):
            analyses.extend(analysis_page.get('NetworkInsightsAnalyses', []))

        if analyses:
            for analysis in analyses:
                analysis_id = analysis.get('NetworkInsightsAnalysisId')
                try:
                    print(f"  Deleting analysis: {analysis_id}")
                    ec2.delete_network_insights_analysis(NetworkInsightsAnalysisId=analysis_id)
                except Exception as e:
                    print(f"  Error deleting analysis {analysis_id}: {e}")
        else:
            print("  No analyses found for this path.")

        # Delete the network insights path.
        try:
            print(f"  Deleting network insights path: {path_id}")
            ec2.delete_network_insights_path(NetworkInsightsPathId=path_id)
        except Exception as e:
            print(f"  Error deleting path {path_id}: {e}")

def main():
    for profile in profiles:
        print(f"\n=== Processing profile: {profile} ===")
        try:
            # Create a boto3 session for the given profile.
            session = boto3.Session(profile_name=profile)
            ec2 = session.client('ec2')
        except Exception as e:
            print(f"Error creating session for profile {profile}: {e}")
            continue

        delete_extra_network_insights_paths_for_client(ec2)

if __name__ == '__main__':
    main()
