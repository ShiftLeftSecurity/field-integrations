# Azure DevOps Contributing Developers

This script identifies unique authors who have committed changes to Azure DevOps repositories within a specified time period (default: last 90 days).

## Prerequisites

- Python 3.6 or higher
- Azure DevOps Personal Access Token (PAT) with Code Read permissions

## Installation

1. Clone this repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

3. Set your Azure DevOps Personal Access Token as an environment variable:

```bash
# For Linux/macOS
export AZURE_DEVOPS_PAT=your_personal_access_token

# For Windows Command Prompt
set AZURE_DEVOPS_PAT=your_personal_access_token

# For Windows PowerShell
$env:AZURE_DEVOPS_PAT="your_personal_access_token"
```

## Usage

```bash
python get_contributing_developers.py --organization https://dev.azure.com/your-organization --project YourProject
```

### Arguments

| Argument | Short | Required | Description |
|----------|-------|----------|-------------|
| `--organization` | `-o` | Yes | Azure DevOps organization URL |
| `--project` | `-p` | Yes | Azure DevOps project name (not required if --organization-wide is used)|
| `--repository` | `-r` | No | Repository name (if not specified, all repositories will be checked) |
| `--days` | `-d` | No | Number of days to look back (default: 90) |
| `--output` | | No | Output format: text, csv, or json (default: text) |
| `--organization-wide` | | No | Analyze all projects in the organization (overrides --project and --repository) |

### Examples

Check all repositories in a project:
```bash
python get_contributing_developers.py --organization https://dev.azure.com/your-organization --project YourProject
```

Check all repositories in the organization:
```bash
python get_contributing_developers.py --organization https://dev.azure.com/your-organization --organization-wide
```

Check a specific repository:
```bash
python get_contributing_developers.py --organization https://dev.azure.com/your-organization --project YourProject --repository YourRepo
```

Get results in CSV format:
```bash
python get_contributing_developers.py --organization https://dev.azure.com/your-organization --project YourProject --output csv
```

Look back 30 days instead of the default 90:
```bash
python get_contributing_developers.py --organization https://dev.azure.com/your-organization --project YourProject --days 30
```

## Output Formats

- **text**: Simple text list of authors with their emails
- **csv**: CSV format with Name and Email columns
- **json**: JSON array with name and email fields
