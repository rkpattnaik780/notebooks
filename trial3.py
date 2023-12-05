markdown_content = """# Security Scan Results

| Image Name | Medium | Low | Unknown | High | Critical |
|------------|-------|-----|---------|------|------|
{table_content}
"""

data = {
    'jupyter-minimal-ubi9-python-3.9-2023b-20231204-73c20d1': {'Medium': 2, 'Low': 1, 'Unknown': 1, 'High': 1},
    'cuda-jupyter-minimal-ubi9-python-3.9-2023b-20231204-73c20d1': {'Medium': 2, 'High': 1, 'Low': 1, 'Unknown': 1}
}

formatted_data = ""
for key, value in data.items():
    formatted_data += f"| {key} |"
    for severity in ['Medium', 'Low', 'Unknown', 'High', 'Critical']:
        count = value.get(severity, 0)  # Get count for the severity, default to 0 if not present
        formatted_data += f" {count} |"
    formatted_data += "\n"

final_markdown = markdown_content.format(table_content=formatted_data)

# Writing to the markdown file
with open("security_scan_results.md", "w") as markdown_file:
    markdown_file.write(final_markdown)