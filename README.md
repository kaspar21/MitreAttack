# MitreAttack

MitreAttack is a tool designed to analyze and process data from the MITRE ATT&CK framework. The tool allows users to perform various analyses on techniques and groups, generate heatmaps, and extract mitigation and detection information.

## Requirements
- Python3
- `requirements.txt` file contains necessary Python packages. Run `pip install -r requirements.txt` to install them.

## Installation
1. Download or clone the repository to your local machine.
2. Unzip the `enterprise-attack.zip` file in the project directory.
3. Navigate to the project directory in the terminal.
4. Run the ./MitreAttack commands to set up the virtual environment and install dependencies:
5. Activate the virtual environment by running:
    source venv/bin/activate

## Usage
Once the setup is complete, you can use the `MitreAttack` script to analyze MITRE ATT&CK data.


## Options
- `help`: Display help information about how to use the tool.
- `csv`: Generate a CSV file with analysis results.
- `json`: Generate a JSON file with analysis results.
- `ws`: Analyze results without subtechniques.
- `all`: Generate all available outputs.

## After using the tool
Once the program finishes, you can find the files in the output/ directory. The JSON file is readable from this link: [https://mitre-attack.github.io/attack-navigator/](url)
