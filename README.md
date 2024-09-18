# ADAPT: Automating APT Campaign and Group Attribution

## Overview

ADAPT is a machine learning-based tool designed to automate the attribution of Advanced Persistent Threat (APT) campaigns and threat groups. In recent years, APTs have posed significant security challenges, affecting industries, governance, and democracies worldwide. These sophisticated threats are difficult to track and attribute, traditionally relying on fragmented intelligence and often resulting in misattribution.

ADAPT addresses this by leveraging various file types (executables, documents, etc.) to link files associated with APT campaigns. It identifies connections at two levels:
1. **Campaign Level**: Cluster malicious files with similar objectives.
2. **Threat Group Level**: Associate samples operated by the same threat actor.



## Dataset
ADAPT has been tested and validated on a comprehensive dataset of APT samples:

*CampaignGroupTags_TestSet*: Includes real-world samples for evaluating the accuracy of campaign and group attribution.

*ADAPTDataset*: A collection of 6,134 APT samples belonging to 92 threat groups. This dataset has been label-standardized for consistent evaluation across different groups.



## Features
- A dataset of heterogeneous file types, including executables and documents.
- APT campaign attribution for both executable and document file types. 
- APT group attribution using a set of linking features across heterogenous file types. 

## Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/SecPriv/adapt.git
   cd adapt
   ```

   
2.  **Install dependencies**: Ensure you have Python 3.x and install the required libraries:
   ```bash
    pip install -r requirements.txt
   ```
    

## Running the System

1. **Generate Features**: Use the feature generation script to process APT samples:

```bash
python feature_processing.py
```

2. **Run the Notebooks**: Several Jupyter notebooks are included for specific analyses:

- CampaignDocumentDomain.ipynb: Focuses on analyzing document-related features for campaign attribution.
- CampaignExecutableDomain.ipynb: Focuses on analyzing executable-related features for campaign attribution.
- GroupAttribution.ipynb: Provides an in-depth approach to group attribution based on the extracted features.



## Contribution
We welcome contributions! If you would like to contribute to ADAPT, follow these steps:

* Fork the repository.
* Create a new branch (git checkout -b feature/YourFeature).
* Commit your changes (git commit -m 'Add new feature').
* Push to the branch (git push origin feature/YourFeature).
* Open a pull request.

## License


## Contact
If you have any questions or encounter issues, feel free to open an issue on GitHub or contact the project maintainers directly.

- **[Aakanksha Saha](aakanksha.saha@seclab.wien)** 





