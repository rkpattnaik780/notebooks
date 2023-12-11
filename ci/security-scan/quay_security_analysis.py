import os
import subprocess
import re
from datetime import date
import requests
from collections import Counter
import fileinput

my_dictionary = {}

commit_id_path = "ci/security-scan/weekly_commit_ids.env"

RELEASE_VERSION_N = "2023b" # os.environ['RELEASE_VERSION_N']
HASH_N = "73c20d1" # os.environ['HASH_N']

IMAGES = [
    "odh-minimal-notebook-image-n",
    # "odh-minimal-gpu-notebook-image-n",
    # "odh-pytorch-gpu-notebook-image-n",
    # "odh-generic-data-science-notebook-image-n",
    # "odh-tensorflow-gpu-notebook-image-n",
    # "odh-trustyai-notebook-image-n",
    # "odh-habana-notebook-image-n",
    # "odh-codeserver-notebook-n",
    # "odh-rstudio-notebook-n",
    # "odh-rstudio-gpu-notebook-n"
]

def process_image(image, commit_id_path, RELEASE_VERSION_N, HASH_N):
    with open(commit_id_path, 'r') as params_file:
        img_line = next(line for line in params_file if re.search(f"{image}=", line))
        img = img_line.split('=')[1].strip()

    registry = img.split('@')[0]

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

# Your existing code here...

# Call the function for each image in IMAGES
for i, image in enumerate(IMAGES):
    process_image(image, commit_id_path, RELEASE_VERSION_N, HASH_N)