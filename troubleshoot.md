# ADAPT – Troubleshooting & Developer Guide

As researchers, we aim to make our code fully reproducible. However, due to the evolving nature of third-party APIs, tools, and malware samples, 
issues may arise. This guide outlines key modules, common pitfalls, and optimization tips for working and extending the ADAPT.

---

## Key Modules & Dependencies

- **Third-party tools & APIs:**  
  - [Censys API](https://search.censys.io/api)
  - [lief](https://lief.quarkslab.com/)  
  - [oletools](https://github.com/decalage2/oletools)  
  - [malcat yara](https://malcat.fr/)  
  - FLOSS and Exiftool (included in `bin/` directory with fixed versions)

---

## Input Structure

├── app
│   ├── css
│   │   ├── **/*.css
│   ├── favicon.ico
│   ├── images
│   ├── index.html
│   ├── js
│   │   ├── **/*.js
│   └── partials/template
├── dist (or build)
├── node_modules

 **Note:**  
The presence of the `{file_hash}.json` VT metadata file is **crucial**.  
It provides the **first submission date**, which is used to narrow the time window in Censys certificate and host queries.

## Running the Feature Extraction

Before running the pipeline, ensure that the file paths are correctly configured for your local environment.

```python
async def main():
    BASE_DIR = r"provide\\the\\folderpath\\malware\\samples"
...
```
Update BASE_DIR to point to your folder containing malware samples.

## Regex Matching Strategies

ADAPT implements two different strategies for regex-based feature extraction:

---

### 1. `feature_processing.py` – Individual Pattern Matching

- **Approach:** Matches each regex individually against string content.
- **Pros:** High flexibility; useful for detailed analysis and debugging.
- **Cons:** Very **slow** on large datasets (~10,000+ samples).
- **Use case:** Debugging or working with small datasets.
- **Reference:** See code block starting around line **1366** in `feature_processing.py`.

---

### 2. `optimized_feature_processing_v1.py` – Combined Pattern Matching

- **Approach:** Combines all regexes into a **single large pattern** using named groups.
- **Pros:** Much **faster**; optimized for batch processing.
- **Cons:** Less fine-grained control; regex patterns must be carefully structured.
- **Optimization:** Strings longer than **2000 characters** are skipped to avoid regex timeouts and high memory usage.

#### Example Code:
```python
candidate_strings = [
    s.get("string").strip()
    for s in all_strings.get("static_strings", [])
    if s.get("string") and len(s.get("string")) < 2000
]
```
You can adjust or remove the string length constraint in the snippet above depending on your dataset and system capabilities.


## Handling Censys API Responses

ADAPT queries the Censys API to extract certificate and host metadata.  
To enable this, you need to set your API credentials as environment variables.  
In the code, the credentials are accessed like this:

```python
censys_api_id = os.getenv("CENSYS_API_ID")
censys_api_secret = os.getenv("CENSYS_API_SECRET")
```

These must be set in your system or runtime environment and avoid hardcoding them into the script for security reasons.
These credentials are required to authenticate your requests with the Censys API and fetch metadata reliably.

The Censys responses can change over time depending on how Censys structures its API.
Refer to the following code block in case the response structure from Censys is not producing expected results.

```python
def censys_certificate_data(domain_name: str, sample_left_date: datetime, sample_right_date: str = "*") -> list:
    sample_left_date_str = sample_left_date.strftime("%Y-%m-%d")

    certificate_query = (
        f"parsed.extensions.subject_alt_name.dns_names:{domain_name}"
        f"AND added_at:[{sample_left_date_str} TO {sample_right_date}]"
    )
```

