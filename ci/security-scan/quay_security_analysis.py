import os
import subprocess
import re
from datetime import date
import requests
from collections import Counter


IMAGES = [
    "odh-minimal-notebook-image-n",
    "odh-minimal-gpu-notebook-image-n",
    "odh-pytorch-gpu-notebook-image-n",
    "odh-generic-data-science-notebook-image-n",
    "odh-tensorflow-gpu-notebook-image-n",
    "odh-trustyai-notebook-image-n"
]

RELEASE_VERSION_N = os.environ['RELEASE_VERSION_N']
HASH_N = os.environ['HASH_N']

my_dictionary = {}

for i, image in enumerate(IMAGES):

    # Read the contents of params.env and extract the image information
    with open('ci/security-scan/weekly_commit_ids.env', 'r') as params_file:
        img_line = next(line for line in params_file if re.search(f"{image}=", line))
        img = img_line.split('=')[1].strip()

    registry = img.split('@')[0]

    # Get source tag from skopeo inspection
    src_tag_cmd = f'skopeo inspect docker://{img} | jq \'.Env[] | select(startswith("OPENSHIFT_BUILD_NAME=")) | split("=")[1]\''
    src_tag = subprocess.check_output(src_tag_cmd, shell=True, text=True).strip().strip('"').replace('-amd64', '')

    regex = f"{src_tag}-{RELEASE_VERSION_N}-\\d+-{HASH_N}"
    latest_tag_cmd = f'skopeo inspect docker://{img} | jq -r --arg regex "{regex}" \'.RepoTags | map(select(. | test($regex))) | .[0]\''

    latest_tag = subprocess.check_output(latest_tag_cmd, shell=True, text=True).strip()

    digest_cmd = f'skopeo inspect docker://{registry}:{latest_tag} | jq .Digest | tr -d \'"\''
    digest = subprocess.check_output(digest_cmd, shell=True, text=True).strip()

    output = f"{registry}@{digest}"

    sha_ = output.split(":")[1]

    url = f"https://quay.io/api/v1/repository/opendatahub/workbench-images/manifest/sha256:{sha_}/security"
    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Authorization": "Bearer 3PZX0UYX6FSENKQ14I1VTHUJ4KGBS8L5LHJ0W1RN7TPHFVQ4P0NR7VQNCZIFRC9B"
    }

    response = requests.get(url, headers=headers)
    data = response.json()

    vulnerabilities = []

    for feature in data['data']['Layer']['Features']:
        if(len(feature['Vulnerabilities']) > 0):
            for vulnerability in feature['Vulnerabilities']:
                vulnerabilities.append(vulnerability)

    severity_levels = [entry.get("Severity", "Unknown") for entry in vulnerabilities]

    # Count occurrences of each severity level
    severity_counts = Counter(severity_levels)

    my_dictionary[latest_tag] = {}

    for severity, count in severity_counts.items():
        my_dictionary[latest_tag][severity] = count

today = date.today()
d2 = today.strftime("%B %d, %Y")

markdown_content = """# Security Scan Results

Date: {d2}

| Image Name | Medium | Low | Unknown | High | Critical |
|------------|-------|-----|---------|------|------|
{table_content}
"""

formatted_data = ""
for key, value in my_dictionary.items():
    formatted_data += f"| {key} |"
    for severity in ['Medium', 'Low', 'Unknown', 'High', 'Critical']:
        count = value.get(severity, 0)  # Get count for the severity, default to 0 if not present
        formatted_data += f" {count} |"
    formatted_data += "\n"

final_markdown = markdown_content.format(table_content=formatted_data)

# Writing to the markdown file
with open("ci/security_scan_results.md", "w") as markdown_file:
    markdown_file.write(final_markdown)