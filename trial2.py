
from collections import Counter

import requests


# sha_ = output.split(":")[1]
sha_ = "cde20ac445d25c70d95042a546334c398ed3fca73e85530f0ffef3cbdb6ec746"

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

my_dictionary = {}

my_dictionary['img'] = {}

# Print the counts
for severity, count in severity_counts.items():
    # print(f"{severity}: {count}")
    # my_dictionary.append()
    my_dictionary['img'][severity] = count

print(my_dictionary)