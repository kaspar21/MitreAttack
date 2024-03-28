from mitreattack.stix20 import MitreAttackData
import csv
from collections import Counter


mitre_attack_data = MitreAttackData("enterprise-attack.json")



def get_name_by_id(id, mitre_attack_data): #attack-pattern--0f20e3cb-245b-4a61-8a91 ==> T1014
    attack_id = mitre_attack_data.get_attack_id(id)
    return attack_id

#============ Get ID by  =====================#

def get_id_by_technique(technique, mitre_attack_data): #T1014 ==> attack-pattern--0f20e3cb-245b-4a61
    obj = mitre_attack_data.get_object_by_attack_id(technique, "attack-pattern")
    if obj:
        return obj.id
    else :
        return ""

def get_id_by_mitigation(mitigation, mitre_attack_data): #T1014 ==> course-of-action--0f20e3cb-245b-4a61
    obj = mitre_attack_data.get_object_by_attack_id(mitigation, "course-of-action")
    if obj:
        return obj.id
    else :
        return ""
    
def get_id_by_detection(detection, mitre_attack_data): #T1014 ==> x-mitre-data-source--0f20e3cb-245b-4a61
    obj = mitre_attack_data.get_object_by_attack_id(detection, "x-mitre-data-source")
    if obj:
        return obj.id
    else :
        return ""

def get_id_by_group(group, mitre_attack_data): #G0038 ==> intrusion-set--0f20e3cb-245b-4a61
    obj = mitre_attack_data.get_object_by_attack_id(group, "intrusion-set")
    if obj:
        return obj.id
    else :
        return ""


#============ Which group use which technique and vice versa =====================#

def WhoUseThatTechnique(id, mitre_attack_data): #Group ==> list of techniques used by the group
    techniques_used_by = mitre_attack_data.get_techniques_used_by_group(id)
    list_techniques = []
    for t in techniques_used_by:
        technique = t["object"]
        list_techniques.append(mitre_attack_data.get_attack_id(technique.id))
    return(list_techniques)

def TechniqueUsedByWho(tech, mitre_attack_data):#technique ==> list of groups using this technique
    groups_using_technique = mitre_attack_data.get_groups_using_technique(get_id_by_technique(tech, mitre_attack_data))
    list_groups = []
    for g in groups_using_technique:
        group = g["object"]
        list_groups.append(mitre_attack_data.get_attack_id(group.id))
    return list_groups



#============ Get Detection/Mitigation for technique  =====================#


def get_detection_for_technique(technique, mitre_attack_data):
    list_detection =[]
    datacomponents_detects = mitre_attack_data.get_datacomponents_detecting_technique(get_id_by_technique(technique, mitre_attack_data))
    for d in datacomponents_detects:
        detection = d["object"]
        datasource = mitre_attack_data.get_object_by_stix_id(detection.x_mitre_data_source_ref)
        list_detection.append(mitre_attack_data.get_attack_id(datasource.id))
    return list_detection

def get_mitigation_for_technique(technique,mitre_attack_data):
    list_mitigation = []
    mitigations_mitigating = mitre_attack_data.get_mitigations_mitigating_technique(get_id_by_technique(technique,mitre_attack_data))
    for m in mitigations_mitigating:
        mitigation = m["object"]
        list_mitigation.append(mitre_attack_data.get_attack_id(mitigation.id))
    return list_mitigation



#============ Get Description =====================#

def get_technique_description(technique):
    mitre_attack_data = MitreAttackData("enterprise-attack.json")
    id = get_id_by_technique(technique,mitre_attack_data)
    #technique = mitre_attack_data.get_techniques(id)
    technique = mitre_attack_data.get_object_by_stix_id(id)
    if technique:
        description = technique.description
        descri = description.replace('\n',' ')
        return descri
    else : 
        return ""
    
def get_mitigation_description(mitigation):
    mitre_attack_data = MitreAttackData("enterprise-attack.json")
    id = get_id_by_mitigation(mitigation,mitre_attack_data)
    #technique = mitre_attack_data.get_techniques(id)
    mitigation = mitre_attack_data.get_object_by_stix_id(id)
    if mitigation:
        description = mitigation.description
        descri = description.replace('\n',' ')
        return descri
    else : 
        return ""
    
def get_detection_description(detection):
    mitre_attack_data = MitreAttackData("enterprise-attack.json")
    id = get_id_by_detection(detection,mitre_attack_data)
    #technique = mitre_attack_data.get_techniques(id)
    detection = mitre_attack_data.get_object_by_stix_id(id)
    if detection:
        description = detection.description
        descri = description.replace('\n',' ')
        return descri
    else : 
        return ""


#============ Get Name =====================#

def get_technique_Name(technique):
    mitre_attack_data = MitreAttackData("enterprise-attack.json")
    id = get_id_by_technique(technique,mitre_attack_data)
    technique = mitre_attack_data.get_object_by_stix_id(id)
    if technique and technique.name != None:
        name = technique.name
        return name
    else : 
        return ""
    
def get_mitigation_name(mitigation):
    mitre_attack_data = MitreAttackData("enterprise-attack.json")
    id = get_id_by_mitigation(mitigation,mitre_attack_data)
    mitigation = mitre_attack_data.get_object_by_stix_id(id)
    if mitigation and mitigation.name != None:
        name = mitigation.name
        return name
    else : 
        return ""

def get_detection_name(detection):
    mitre_attack_data = MitreAttackData("enterprise-attack.json")
    id = get_id_by_detection(detection,mitre_attack_data)
    detection = mitre_attack_data.get_object_by_stix_id(id)
    if detection and detection.name != None:
        name = detection.name
        return name
    else : 
        return ""

#============ Others =====================#


def sort_list(list, mitre_attack_data):#Sort list of groups, [Aquatic Panda,G0117,Andariel,APT29] ==> [G0117, G0081, G1718]
    G_list = []
    rest_list = []
    all_list = []
    for terme in list:
        if terme.startswith('G'):
            G_list.append(terme)
        else:
            rest_list.append(terme)
    all_list.extend(G_list)
    for each in rest_list :
        try:
            all_list.append(NameToGroup(each, mitre_attack_data))
        except:
            print(f"Error with {each}")
            continue
    return all_list


def NameToGroup(name, mitre_attack_data): #Aquatic Panda ==> G0117
    groups = mitre_attack_data.get_groups_by_alias(name)
    for group in groups:
        Gchiffre = mitre_attack_data.get_attack_id(group.id)
    return Gchiffre








if __name__ == "__main__":
    #techniques = ['M1018', 'M1022', 'M1052', 'M1018']
    #detec  = ['DS0009','DS0022','DS0029','DS0017','DS0002']
    mitre_attack_data = MitreAttackData("enterprise-attack.json")
    i=0
    u='Aquatic Panda'
    zz = NameToGroup(u,mitre_attack_data)
    print(f"{u} is {zz}")
    

    """
    mitre_attack_data = MitreAttackData("enterprise-attack.json")
    techniques = ['T1037', 'T1119', 'T1059', 'T1613', 'T1098', 'T1037', 'T1037', 'T1037', 'T1119']
    for tech in techniques : 
        id_tech = get_id_by_technique(tech,mitre_attack_data)
        descri = get_technique_description(id_tech,mitre_attack_data)
        print(descri)
    """