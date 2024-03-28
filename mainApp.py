import json
import sys
import collections
import time
import os
import re
from collections import Counter
from generate_heatmap import generate_attck_heatmap_json , generate_attck_heatmap_csv
from functions import WhoUseThatTechnique, get_id_by_group, sort_list, get_mitigation_name, get_detection_description, get_mitigation_for_technique, get_mitigation_description, get_detection_name, get_detection_for_technique
from mitreattack.stix20 import MitreAttackData
from tqdm import tqdm

filename = time.strftime("%H_%M_%S-%d%m%y")
dirdate = time.strftime("%d%m%y")
dirname = f"output/output_{dirdate}"


def main():
    arguments = sys.argv[1:]

    if 'help' in arguments : 
        print("Welcome on Mitre Att&ck program")
        print("./MitreAttack csv   ---> generate csv file")
        print("./MitreAttack json  ---> generate json file")
        print("./MitreAttack ws    ---> results without subtechniques")
        print("./MitreAttack all   ---> generate all.")
        return
    
    if not os.path.exists(dirname):
        os.makedirs(dirname)

    print(f"Arguments : {arguments}")
    mad = MitreAttackData("enterprise-attack.json")
    #Open the txt file
    input_filepath = "input/input.txt"
    with open(input_filepath, 'r') as file:
        input_data = file.read()
                                                                                                                                                  
    #Analyse the texte file
    lines = [line.strip() for line in input_data.split('\n') if line.strip()]
    print('Analysis of the groups and techniques that you entrusted to me...')
    technique_pattern = re.compile(r'^T\d{4}(\.\d{3})?$')
    techniques = [line for line in lines if technique_pattern.match(line)] #List of techniques
    groups_disorder = [line for line in lines if not technique_pattern.match(line)]#List of groups with G**, A**, Atlantic Panda
    sorted_group = sort_list(groups_disorder, mad) # List of groups cleanliness with G**
    technique_count = collections.Counter(techniques) #How many techniques
    group_count = collections.Counter(sorted_group) #How many groups
    everytechniques = techniques

    #Start writing in the txtfile
    txtfile = dirname+"/"+ filename + ".txt"
    with open(txtfile, 'w') as f:
        f.write("---GROUPS---\n")
        for groups, count in sorted(group_count.items(),key=lambda x: x[1], reverse=True):
            f.write(f"{groups} - {count}\n")
        if technique_count : 
            f.write("\n---TECHNIQUES---\n")
            for technique, count in sorted(technique_count.items(),key=lambda x: x[1], reverse=True):
                f.write(f"{technique} - {count}\n")
    
#=========================================================================#

    #Analyse techniques used by groups 
    all_techniques = [] #List of  all techniques used by groups with subtechniques (['T1204.001', 'T1553.002'])
    heatmap_data = {}
    for group in sorted_group :
        id_group = get_id_by_group(group, mad)
        techniques_used_by = WhoUseThatTechnique(id_group, mad)
        all_techniques.extend(techniques_used_by)
    everytechniques.extend(all_techniques) #User-given techniques + user-given techniques used by groups
    technique_without_subtechniques = [technique.split('.')[0] for technique in all_techniques]
    
    technique_counts = Counter(all_techniques)# dict of techniques used by groups and how often they are used ({'T1204.001': 2, 'T1078': 2})
    scoremax = max(technique_counts.values())

    with open(txtfile, 'a') as f:
        f.write("\nWhich techniques are using by this groups  ?\n")
        f.write("From most to least used:\n")
        for technique, count in sorted(technique_counts.items(),key=lambda x: x[1], reverse=True):
            f.write(f"{technique} - {count}\n")
            #HEATMAP DATA
            if technique in heatmap_data:
                heatmap_data[technique] += count
            else:
                heatmap_data[technique] = count
    
    if not ('json' in arguments or 'all' in arguments):
        print("You did not request a json file")
    else : 
        jsonfilename = dirname+"/"+ filename + ".json"
        print("Creating the json file...")
        generate_attck_heatmap_json(heatmap_data, jsonfilename,scoremax) #Generate heatmap of technique used by groups in input
    
    
    if not ('csv' in arguments or 'all' in arguments):
        print("You did not request a csv file")
    else : 
        csvfilename  = dirname + "/" + filename + ".csv"
        print("Creating the csv file...")
        generate_attck_heatmap_csv(heatmap_data,csvfilename)




#====================================================================#
    if not ('ws' in arguments or 'all' in arguments):
        print("You did not request to search without subtechniques")
    else : 
        technique_counts_without_sub = Counter(technique_without_subtechniques)# dict of techniques used by groups and how often they are used ({'T1204.001': 2, 'T1078': 2})
        scoremax_without = max(technique_counts_without_sub.values())
        heatmap_data_without = {}
        with open(txtfile, 'a') as f:
            f.write("\nWithout subtechniques : Which techniques are using by this groups  ?\n")
            f.write("From most to least used:\n")
            for technique, count in sorted(technique_counts_without_sub.items(),key=lambda x: x[1], reverse=True):
                f.write(f"{technique} - {count}\n")
                #HEATMAP DATA
                if technique in heatmap_data_without:
                    heatmap_data_without[technique] += count
                else:
                    heatmap_data_without[technique] = count

        jsonfilename = dirname+"/"+ filename + "withoutsubtechniques.json"
        generate_attck_heatmap_json(heatmap_data_without, jsonfilename,scoremax_without) # Generate heatmap of technique used by groups in input
    csvfilenamews  = dirname + "/" + filename + "ws.csv"
    if ('all' in arguments) :
        csvfilenamews  = dirname + "/" + filename + "ws.csv"
        generate_attck_heatmap_csv(heatmap_data,csvfilenamews)

    if ('ws' in arguments and 'csv' in arguments ):
        csvfilenamews  = dirname + "/" + filename + "ws.csv"
        generate_attck_heatmap_csv(heatmap_data,csvfilenamews)
#====================================================================#
#======================== MITIGATION ==================================#
    list_mitigation = []
    for tech in everytechniques :
        mitigation_for_tech = get_mitigation_for_technique(tech,mad)
        list_mitigation.extend(mitigation_for_tech)
    
    top_10_mitigations = Counter(list_mitigation).most_common(10)

    with open(txtfile, 'a') as f:
        f.write("\n---TOP 10 MITIGATIONS---\n")
        f.write("\nID    :   Name          xCount   :Description\n")
        with tqdm(total=10,desc="Mitigations...") as pbar:
            for mitigation, count in top_10_mitigations:
                description = get_mitigation_description(mitigation)
                name = get_mitigation_name(mitigation)
                f.write(f"{mitigation} : {name} x{count} : {description} \n")
                pbar.update(1)


#======================== DETECTIONS ==================================#
    list_detections = [] 
    for tech in techniques :
        detection_for_tech = get_detection_for_technique(tech, mad)
        list_detections.extend(detection_for_tech)
    
    top_10_detections = Counter(list_detections).most_common(10)
    
    with open(txtfile, 'a') as f:
        f.write("\n---TOP 10 DETECTIONS---\n")
        f.write("\nID    :   Name          xCount   :Description\n")
        with tqdm(total=10,desc="Detections...") as pbar:
            for detection, count in top_10_detections:
                description = get_detection_description(detection)
                name = get_detection_name(detection)
                f.write(f"{detection} : {name} x{count} : {description} \n")
                pbar.update(1)


#============ Print txt file results in the console =====================#
    print("That's it, it's finished!")
    with open(txtfile, 'r') as f:
        content = f.read()
        print("\n\n")
        print(content)
    print("\n\nPlease find your files in the output folder !")




if __name__ == "__main__":
    main()