import argparse
import AzureApi
import datetime

# This function will print passed message and correct arg value
def print_arg_messages(parser, printMessage):
    print(printMessage)
    parser.print_usage()
    parser.print_help()
    quit()

def parse_args():
    parser = argparse.ArgumentParser(description="Find developers contributing to Azure Repos in the last 90 days")
    parser.add_argument('--org', type=str, help='Customer Azure Organization Name')
    parser.add_argument('--username', type=str, help='Customer Azure username')
    parser.add_argument('--accessToken', type=str, help='Customer Azure Access Token')

    # Added argument of the n top projects to retrieve, default is 100
    parser.add_argument('--top', type=int, help='Number projects to retrieve')

    args = parser.parse_args()

    if args.org is None:
        print_arg_messages(parser, 'Organization name is required --org')

    if args.username is None:
        print_arg_messages(parser, 'Azure username is required --username')

    if args.accessToken is None:
        print_arg_messages(parser, 'Access token is required --accessToken')

    # Check if the top arg was set, if not set to 100 as default
    if args.top is None:
        args.top = 100
        print('Max number of projects is set to 100')
    
    # Limit max of projects to retrieve to 100,000
    elif args.top > 100000:
        print_arg_messages(parser, 'The number of projects to retrieve can not be greater than 100000')
    else :
        print('Number of projects to retrieve was set to ', args.top)

    return args


args = parse_args()
AzureApi.username = args.username
AzureApi.accessToken = args.accessToken

projects_response_obj = AzureApi.azureProjects(args.org, args.top)

dt_utc_now = datetime.datetime.utcnow()

unique_authors = set()

# Accumulated Variable to count the projects retrieved and print the value at the end
totalProjects = 0

# Across all repos in all projects
print('ProjectName, RepoId, RepoName, CommitId, AuthorName, AuthorEmail, AuthorDate')
for next_project in projects_response_obj['value']:
    totalProjects += 1
    project_id = next_project['id']

    # Get all repos in this project
    repos_response_obj = AzureApi.azureRepos(args.org, project_id)
    for next_repo in repos_response_obj['value']:
        repo_id = next_repo['id']
        # Get all commits in this repo
        all_commits = AzureApi.azureCommits(args.org, project_id, repo_id)
        for next_commit in all_commits:
            print('%s,%s,%s,%s,%s,%s,%s' % (next_project['name'], next_repo['id'], next_repo['name'], next_commit['commitId'], next_commit['author']['name'], next_commit['author']['email'], next_commit['author']['date']))

            str_author_date = next_commit['author']['date']
            dt_author_date = AzureApi.azureDateFormat(str_author_date)
            isWithinLookback = AzureApi.isWithinLookback(dt_author_date, dt_utc_now)

            author_name = next_commit['author']['name']
            author_email = next_commit['author']['email']
            if isWithinLookback:
                str_name_and_email = '%s <%s>' % (author_name, author_email)
                unique_authors.add(str_name_and_email)

            print()

    print()

print('\n\nUnique contributors in the last Lookback/90 days:')

for a in unique_authors:
    print(a)

# Print the total of projects retrieved
print('\n\nTotal Projects found: ', totalProjects)
print('\n\nTotal Unique Users found: ', len(unique_authors))

quit()
