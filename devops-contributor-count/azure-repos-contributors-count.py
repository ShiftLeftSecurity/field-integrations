import AzureDevOps
import argparse
import datetime

def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Count developers in Azure Repos active in the last 90 days")
    parser.add_argument('--organization', type=str, help='Your Azure DevOps Organization')
    parser.add_argument('--username', type=str, help='Your Azure DevOps username')
    parser.add_argument('--pat', type=str, help='Your Azure DevOps Personal Access Token')

    # Added argument of the n top projects to retrieve, default is 100
    parser.add_argument('--top', type=int, help='The top n projects to return')

    args = parser.parse_args()

    if args.organization is None:
        print('You must specify --organization')
        parser.print_usage()
        parser.print_help()
        quit()

    if args.username is None:
        print('You must specify --username')
        parser.print_usage()
        parser.print_help()
        quit()

    if args.pat is None:
        print('You must specify --pat')
        parser.print_usage()
        parser.print_help()
        quit()

    # Check if the top arg was set, if not set to 100 as default
    if args.top is None:
        args.top = 100
        print('Number of projects to retrieve was set to 100')
    
    # Set the max of projects to retrieve to 100k in order to not stress the server
    elif args.top > 100000:
        print('The number of projects to retrieve can not be greater than 100000')
        parser.print_usage()
        parser.print_help()
        quit()    
    else :
        print('Number of projects to retrieve was set to ' ,args.top)

    return args


args = parse_command_line_args()
AzureDevOps.username = args.username
AzureDevOps.token_str = args.pat

projects_response_obj = AzureDevOps.azure_devops_list_projects(args.organization, args.top)
# print(test_list_projects_response_json_obj)

dt_utc_now = datetime.datetime.utcnow()

unique_authors = set()

# Accumulated Variable to count the projects retrieved and print the value at the end
totalProjects = 0

# Across all repos in all projects
for next_project in projects_response_obj['value']:
    print('project name: %s' % next_project['name'])
    totalProjects += 1
    project_id = next_project['id']

    # Get all repos in this project
    repos_response_obj = AzureDevOps.azure_devops_list_repos(args.organization, project_id)
    for next_repo in repos_response_obj['value']:
        print('  - repo id: %s' % next_repo['id'])
        print('  - repo name: %s' % next_repo['name'])

        repo_id = next_repo['id']
        # Get all commits in this repo
        all_commits = AzureDevOps.azure_devops_get_commits(args.organization, project_id, repo_id)
        for next_commit in all_commits:
            print('    - commit commitId: %s' % next_commit['commitId'])
            print('    - commit author-name: %s' % next_commit['author']['name'])
            print('    - commit author-email: %s' % next_commit['author']['email'])
            print('    - commit author-date: %s' % next_commit['author']['date'])

            str_author_date = next_commit['author']['date']
            dt_author_date = AzureDevOps.get_datetime_from_azure_devops_format(str_author_date)
            is_within_90_days = AzureDevOps.is_within_90_days(dt_author_date, dt_utc_now)

            author_name = next_commit['author']['name']
            author_email = next_commit['author']['email']
            print(author_email)
            if is_within_90_days:
                str_name_and_email = '%s <%s>' % (author_name, author_email)
                unique_authors.add(str_name_and_email)

            print()

    print()

print('\n\nUnique authors contributing in the last 90 days:')

for a in unique_authors:
    print(a)

# Print the total of projects retrieved
print('\n\nTotal Projects found: ', totalProjects)
print('\n\nTotal Unique Users found: ', len(unique_authors))

quit()
