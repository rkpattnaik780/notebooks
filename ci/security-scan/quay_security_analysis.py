import os
import subprocess
import re
from datetime import date
import requests
from collections import Counter
import fileinput

my_dictionary = {}

commit_id_path = "ci/security-scan/weekly_commit_ids.env"


IMAGES = [
    "odh-minimal-notebook-image-n",
    "odh-runtime-minimal-notebook-image-n",
    "odh-runtime-data-science-notebook-image-n",
    "odh-minimal-gpu-notebook-image-n",
    "odh-pytorch-gpu-notebook-image-n",
    "odh-generic-data-science-notebook-image-n",
    "odh-tensorflow-gpu-notebook-image-n",
    "odh-trustyai-notebook-image-n",
    "odh-habana-notebook-image-n",
    "odh-codeserver-notebook-n",
    "odh-rstudio-notebook-n",
    "odh-rstudio-gpu-notebook-n"
]

IMAGES_N_1 = [
    "odh-minimal-notebook-image-n-1",
    "odh-minimal-gpu-notebook-image-n-1",
    "odh-pytorch-gpu-notebook-image-n-1",
    "odh-runtime-data-science-notebook-image-n-1",
    "odh-generic-data-science-notebook-image-n-1",
    "odh-tensorflow-gpu-notebook-image-n-1",
    "odh-trustyai-notebook-image-n-1",
    "odh-habana-notebook-image-n-1",
    "odh-codeserver-notebook-n-1",
    "odh-rstudio-notebook-n-1",
    "odh-rstudio-gpu-notebook-n-1"
]

def process_image(image, commit_id_path, RELEASE_VERSION_N, HASH_N):
    with open(commit_id_path, 'r') as params_file:
        img_line = next(line for line in params_file if re.search(f"{image}=", line))
        img = img_line.split('=')[1].strip()

    registry = img.split('@')[0]

    src_tag_cmd = f'skopeo inspect docker://{img} | jq \'.Env[] | select(startswith("OPENSHIFT_BUILD_NAME=")) | split("=")[1]\''
    src_tag = subprocess.check_output(src_tag_cmd, shell=True, text=True).strip().strip('"').replace('-amd64', '')


    regex = "" # f"{src_tag}-{RELEASE_VERSION_N}-\\d+-{HASH_N}"

    if RELEASE_VERSION_N == "":
        regex = f"{src_tag}-(\\d+-)?{HASH_N}"
    else:
        regex = f"{src_tag}-{RELEASE_VERSION_N}-\\d+-{HASH_N}"

    latest_tag_cmd = f'skopeo inspect docker://{img} | jq -r --arg regex "{regex}" \'.RepoTags | map(select(. | test($regex))) | .[0]\''
    print("latest_tag_cmd")
    print(latest_tag_cmd)
    latest_tag = subprocess.check_output(latest_tag_cmd, shell=True, text=True).strip()

    digest_cmd = f'skopeo inspect docker://{registry}:{latest_tag} | jq .Digest | tr -d \'"\''
    digest = subprocess.check_output(digest_cmd, shell=True, text=True).strip()

    if digest is None:
        return

    output = f"{registry}@{digest}"

    print("output")
    print(output)

    sha_ = output.split(":")[1]

    url = f"https://quay.io/api/v1/repository/opendatahub/workbench-images/manifest/sha256:{sha_}/security"
    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Authorization": "Bearer 3PZX0UYX6FSENKQ14I1VTHUJ4KGBS8L5LHJ0W1RN7TPHFVQ4P0NR7VQNCZIFRC9B_1"
    }

    response = requests.get(url, headers=headers)
    data = response.json()

    vulnerabilities = []

    for feature in data['data']['Layer']['Features']:
        if(len(feature['Vulnerabilities']) > 0):
            for vulnerability in feature['Vulnerabilities']:
                vulnerabilities.append(vulnerability)

    severity_levels = [entry.get("Severity", "Unknown") for entry in vulnerabilities]
    severity_counts = Counter(severity_levels)

    my_dictionary[latest_tag] = {}
    my_dictionary[latest_tag]['sha']= digest

    for severity, count in severity_counts.items():
        my_dictionary[latest_tag][severity] = count
    
    for line in fileinput.input(commit_id_path, inplace=True):
        if line.startswith(f"{image}="):
            line = f"{image}={output}\n"
        print(line, end="")


RELEASE_VERSION_N = os.environ['RELEASE_VERSION_N']
HASH_N = os.environ['HASH_N']

# Call the function for each image in IMAGES
for i, image in enumerate(IMAGES):
    process_image(image, commit_id_path, RELEASE_VERSION_N, HASH_N)

today = date.today()
d2 = today.strftime("%B %d, %Y")

formatted_data = ""
for key, value in my_dictionary.items():
    formatted_data += f"| [{key}](https://quay.io/repository/opendatahub/workbench-images/manifest/{my_dictionary[key]['sha']}?tab=vulnerabilities) |"
    for severity in ['Medium', 'Low', 'Unknown', 'High', 'Critical']:
        count = value.get(severity, 0)  # Get count for the severity, default to 0 if not present
        formatted_data += f" {count} |"
    formatted_data += "\n"

my_dictionary = {}

RELEASE_VERSION_N_1 = os.environ['RELEASE_VERSION_N_1']
HASH_N_1 = os.environ['HASH_N_1']

for i, image in enumerate(IMAGES_N_1):
    process_image(image, commit_id_path, RELEASE_VERSION_N_1, HASH_N_1)

branch_n_data = ""
for key, value in my_dictionary.items():
    branch_n_data += f"| [{key}](https://quay.io/repository/opendatahub/workbench-images/manifest/{my_dictionary[key]['sha']}?tab=vulnerabilities) |"
    for severity in ['Medium', 'Low', 'Unknown', 'High', 'Critical']:
        count = value.get(severity, 0)  # Get count for the severity, default to 0 if not present
        branch_n_data += f" {count} |"
    branch_n_data += "\n"

markdown_content = """# Security Scan Results

Date: {todays_date}

# Branch N

| Image Name | Medium | Low | Unknown | High | Critical |
|------------|-------|-----|---------|------|------|
{table_content}

# Branch N - 1

| Image Name | Medium | Low | Unknown | High | Critical |
|------------|-------|-----|---------|------|------|
{branch_n}
"""

final_markdown = markdown_content.format(table_content=formatted_data, todays_date=d2, branch_n=branch_n_data)

# Writing to the markdown file
with open("ci/security-scan/security_scan_results.md", "w") as markdown_file:
    markdown_file.write(final_markdown)