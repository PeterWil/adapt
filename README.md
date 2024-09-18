# ADAPT: Automating APT Campaign and Group Attribution

## Overview

ADAPT is a machine learning-based tool designed to automate the attribution of Advanced Persistent Threat (APT) campaigns and threat groups. In recent years, APTs have posed significant security challenges, affecting industries, governance, and democracies worldwide. These sophisticated threats are difficult to track and attribute, traditionally relying on fragmented intelligence and often resulting in misattribution.

ADAPT addresses this by leveraging various file types (executables, documents, etc.) to link files associated with APT campaigns. It identifies connections at two levels:
1. **Campaign Level**: Cluster files with similar objectives.
2. **Threat Group Level**: Associate samples operated by the same threat actor.

The system has been evaluated using MITRE datasets, alongside a standardized dataset of over 6,000 APT samples from 92 threat groups. 
## Features
- Supports heterogeneous file types, including executables and documents.
- Detects linkages between files to attribute them to campaigns or groups.
- Evaluated on large datasets with real-world APT samples.

## Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/SecPriv/adapt.git
   cd adapt
