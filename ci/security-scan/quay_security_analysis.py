import os
import subprocess
import re
from datetime import date
import requests
from collections import Counter
import fileinput


IMAGES = [
    "odh-minimal-notebook-image-n",
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

IMAGES_N = [
    "odh-minimal-notebook-image-n",
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

def get_image_security_reports(commit_id_path, IMAGES):
    for i, image in enumerate(IMAGES):

        # Read the contents of params.env and extract the image information
        with open(commit_id_path, 'r') as params_file:
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

        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Authorization": "Bearer 3PZX0UYX6FSENKQ14I1VTHUJ4KGBS8L5LHJ0W1RN7TPHFVQ4P0NR7VQNCZIFRC9B_1"
        }

        url = f"https://quay.io/api/v1/repository/opendatahub/workbench-images/manifest/sha256:{digest}/security"

        response = requests.get(url, headers=headers)
        data = response.json()

        print(data)

        vulnerabilities = []

        for feature in data['data']['Layer']['Features']:
            if(len(feature['Vulnerabilities']) > 0):
                for vulnerability in feature['Vulnerabilities']:
                    vulnerabilities.append(vulnerability)

        severity_levels = [entry.get("Severity", "Unknown") for entry in vulnerabilities]

        # Count occurrences of each severity level
        severity_counts = Counter(severity_levels)

        my_dictionary[latest_tag] = {}
        my_dictionary[latest_tag]['sha']= digest

        for severity, count in severity_counts.items():
            my_dictionary[latest_tag][severity] = count
        
        for line in fileinput.input(commit_id_path, inplace=True):
            if line.startswith(f"{image}="):
                line = f"{image}={output}\n"
            print(line, end="")

        formatted_data = ""
        for key, value in my_dictionary.items():
            formatted_data += f"| [{key}](https://quay.io/repository/opendatahub/workbench-images/manifest/{my_dictionary[key]['sha']}?tab=vulnerabilities) |"
            for severity in ['Medium', 'Low', 'Unknown', 'High', 'Critical']:
                count = value.get(severity, 0)  # Get count for the severity, default to 0 if not present
                formatted_data += f" {count} |"
            formatted_data += "\n"

commit_id_path = "ci/security-scan/weekly_commit_ids.env"

RELEASE_VERSION_N = "2023b" # os.environ['RELEASE_VERSION_N'] # 2023b
HASH_N = "73c20d1" # os.environ['HASH_N']

my_dictionary = {}

today = date.today()
d2 = today.strftime("%B %d, %Y")

main_security_report = get_image_security_reports

markdown_content = """# Security Scan Results

Date: {todays_date}

## Main Branch

| Image Name | Medium | Low | Unknown | High | Critical |
|------------|-------|-----|---------|------|------|
{main_security_report}
"""

formatted_data = get_image_security_reports(commit_id_path, IMAGES)

final_markdown = markdown_content.format(main_security_report=formatted_data, todays_date=d2, n_security_report="", n_1_security_report="")

# Writing to the markdown file
with open("ci/security-scan/security_scan_results.md", "w") as markdown_file:
    markdown_file.write(final_markdown)