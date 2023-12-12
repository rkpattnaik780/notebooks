# import requests

# headers = {
#     "X-Requested-With": "XMLHttpRequest",
#     "Authorization": "Bearer IMUSI3RVH0FQ426LNP1CY7Q1MT4KXMZMWE6W5RQ2JYERP2RJQFL8LS1OF3Y18WOK"
# }

# url = f"https://quay.io/api/v1/repository/rpattnai/workbench-images/manifest/sha256:f802620c6e5aff5e1e719574b57253e07fccee101600a0b6bb96723827f379fd/security\?vulnerabilities\=true"

# response = requests.get(url, headers=headers)
# data = response.json()

# print(data)

import requests

url = "https://quay.io/api/v1/repository/opendatahub/workbench-images/manifest/sha256:7eea86c98f20ed3c58c838e40369d68219c13967daafc52970412f669f621522/security?vulnerabilities"
headers = {
    "X-Requested-With": "XMLHttpRequest",
    "Authorization": "Bearer 3PZX0UYX6FSENKQ14I1VTHUJ4KGBS8L5LHJ0W1RN7TPHFVQ4P0NR7VQNCZIFRC9B_1",
}

response = requests.get(url, headers=headers)

if response.status_code == 200:
    vulnerabilities_data = response.json()
    print(vulnerabilities_data)
    # Process vulnerabilities_data as needed
else:
    print(f"Error: {response.status_code}")