# ADAPT: Automating APT Campaign and Group Attribution

## Overview

ADAPT is a machine learning-based tool designed to automate the attribution of Advanced Persistent Threat (APT) campaigns and threat groups. In recent years, APTs have posed significant security challenges, affecting industries, governance, and democracies worldwide. These sophisticated threats are difficult to track and attribute, traditionally relying on fragmented intelligence and often resulting in misattribution.

ADAPT addresses this by leveraging various file types (executables, documents, etc.) to link files associated with APT campaigns. It identifies connections at two levels:
1. **Campaign Level**: Cluster malicious files with similar objectives.
2. **Threat Group Level**: Associate samples operated by the same threat actor.

The system has been evaluated using MITRE datasets, alongside a standardized dataset of over 6,000 APT samples from 92 threat groups. 
## Features
- A dataset of heterogeneous file types, including executables and documents.
- APT campaign attribution for both executable and document file types. 
- APT group attribution using a set of linking features across heterogenous file types. 

## Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/SecPriv/adapt.git
   cd adapt


2.  **Install dependencies:** Ensure you have Python 3.x and install the required libraries:
```bash
pip install -r requirements.txt

3. **Run the feature generator:** Follow the steps in the provided Jupyter notebooks to process APT samples using the feature generation script.
```bash
python feature_processing.py

