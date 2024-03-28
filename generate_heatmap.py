import json
import csv
from functions import get_technique_description, get_technique_Name
from tqdm import tqdm


def generate_attck_heatmap_json(heatmap_data, output_file,scoremax):
    metadata = {
        "name": "ATT&CK Heatmap ",
        "description": "Heatmap of ATT&CK techniques",
        "domain": "enterprise-attack",
        "versions": {
            "attack": "14",
            "navigator": "4.9.4",
            "layer": "4.5"
        },
        "techniques": [],
        "gradient": {
		"colors": [
			"#8ec843ff",
			"#ffe766ff",
			"#ff6666ff"
		],
		"minValue": 0,
		"maxValue": scoremax
	},
    }

    total_items = len(heatmap_data)
    with tqdm(total=total_items,desc="Writing JSON") as pbar : 
        for technique, score in heatmap_data.items():
            metadata["techniques"].append({
                "techniqueID": technique,
                "score": score
            })
            pbar.update(1)
    with open(output_file, "w") as f:
        json.dump(metadata, f, indent=4)


def generate_attck_heatmap_csv(heatmap_data, output_file):
    scoremax = max(heatmap_data.values())
    total_items = len(heatmap_data)
    with open(output_file, 'w' , newline='') as csvfile :
        writer = csv.writer(csvfile)
        writer.writerow(['Technique','Score','Name','Description'])
        with tqdm(total=total_items, desc="Genrating CSV", unit="techniques") as pbar :
            for technique, score in heatmap_data.items() : 
                if (score >= scoremax/2) : 
                    descri = get_technique_description(technique)
                    name = get_technique_Name(technique)
                    writer.writerow([technique,score,name,descri])
                    pbar.update(1)
                else : 
                    break