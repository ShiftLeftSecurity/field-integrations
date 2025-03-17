#!/usr/bin/env python3
"""
Script to get a list of unique authors who have committed changes in the last 90 days
for a given repository or all repositories in an Azure DevOps organization.
"""

import argparse
import datetime
import os
import sys
from typing import List, Set, Dict, Optional, Any

from azure.devops.connection import Connection
from azure.devops.exceptions import AzureDevOpsServiceError
from azure.devops.v7_0.git.models import GitQueryCommitsCriteria
from msrest.authentication import BasicAuthentication


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Get a list of unique authors who have committed changes in the last 90 days."
    )
    parser.add_argument(
        "--organization", "-o", required=True, help="Azure DevOps organization URL"
    )
    parser.add_argument(
        "--project", "-p", required=True, help="Azure DevOps project name"
    )
    parser.add_argument(
        "--repository", "-r", help="Repository name (if not specified, all repositories will be checked)"
    )
    parser.add_argument(
        "--days", "-d", type=int, default=90, help="Number of days to look back (default: 90)"
    )
    parser.add_argument(
        "--output", choices=["text", "csv", "json"], default="text",
        help="Output format (default: text)"
    )
    
    return parser.parse_args()


def get_connection(organization_url: str) -> Connection:
    """Create a connection to Azure DevOps using PAT from environment variable."""
    # Get PAT from environment variable
    personal_access_token = os.environ.get("AZURE_DEVOPS_PAT")
    if not personal_access_token:
        print("Error: AZURE_DEVOPS_PAT environment variable is not set.", file=sys.stderr)
        print("Please set it with your Personal Access Token.", file=sys.stderr)
        sys.exit(1)
        
    credentials = BasicAuthentication("", personal_access_token)
    return Connection(base_url=organization_url, creds=credentials)


def get_repositories(connection: Connection, project: str) -> List[Any]:
    """Get all repositories in a project."""
    git_client = connection.clients.get_git_client()
    try:
        return git_client.get_repositories(project=project)
    except AzureDevOpsServiceError as e:
        print(f"Error getting repositories: {e}", file=sys.stderr)
        sys.exit(1)


def get_commits_since_date(
    connection: Connection, 
    project: str, 
    repository_id: str, 
    since_date: datetime.datetime
) -> List[Any]:
    """Get all commits in a repository since a given date."""
    git_client = connection.clients.get_git_client()
    try:
        # Create a proper GitQueryCommitsCriteria object
        search_criteria = GitQueryCommitsCriteria()
        search_criteria.from_date = since_date.isoformat()
        
        return git_client.get_commits(
            repository_id=repository_id,
            project=project,
            search_criteria=search_criteria
        )
    except AzureDevOpsServiceError as e:
        print(f"Error getting commits: {e}", file=sys.stderr)
        return []


def get_unique_authors(commits: List[Any]) -> Set[str]:
    """Extract unique author names and emails from commits."""
    authors = set()
    for commit in commits:
        author = commit.author
        author_str = f"{author.name} <{author.email}>"
        authors.add(author_str)
    return authors


def output_results(authors: Set[str], format_type: str, days: int):
    """Output the results in the specified format."""
    if format_type == "text":
        authors_n = len(authors)
        if authors_n <1:
            print(f"Found {authors_n} unique authors in the last {days} days.")
        else:
            print(f"Found {authors_n} unique authors in the last {days} days:")
            for author in sorted(authors):
                print(f"- {author}")
    
    elif format_type == "csv":
        print("Name,Email")
        for author in sorted(authors):
            name, email = author.split(" <")
            email = email.rstrip(">")
            print(f'"{name}","{email}"')
    
    elif format_type == "json":
        import json
        authors_list = []
        for author in authors:
            name, email = author.split(" <")
            email = email.rstrip(">")
            authors_list.append({"name": name, "email": email})
        print(json.dumps(authors_list, indent=2))


def main():
    """Main function."""
    args = parse_arguments()
    
    # Calculate the date 'days' days ago
    since_date = datetime.datetime.now() - datetime.timedelta(days=args.days)
    
    # Connect to Azure DevOps
    connection = get_connection(args.organization)
    
    # Get repositories
    if args.repository:
        # For a specific repository, we need to find it by name
        git_client = connection.clients.get_git_client()
        try:
            repositories = [git_client.get_repository(args.repository, args.project)]
        except AzureDevOpsServiceError as e:
            print(f"Error: Repository '{args.repository}' not found: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        repositories = get_repositories(connection, args.project)
    
    all_authors = set()
    
    # Process each repository
    for repo in repositories:
        print(f"Processing repository: {repo.name}", file=sys.stderr)
        commits = get_commits_since_date(connection, args.project, repo.id, since_date)
        authors = get_unique_authors(commits)
        all_authors.update(authors)
        print(f"Found {len(authors)} authors in {repo.name}", file=sys.stderr)
    
    # Output the results
    output_results(all_authors, args.output, args.days)


if __name__ == "__main__":
    main()
