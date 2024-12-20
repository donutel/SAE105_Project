import os
import pandas as pd

# Chemin du dossier contenant les fichiers ICS
folder_path = r"C:\Users\HP\OneDrive\Desktop\ics"

# Fonction pour lire un fichier ICS et extraire les informations importantes
def parse_ics_file(file_path):
    events = []
    current_event = {}
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if line.startswith("BEGIN:VEVENT"):
                current_event = {}
            elif line.startswith("END:VEVENT"):
                events.append(current_event)
            elif line.startswith("DTSTART:"):
                current_event["Start Date"] = line.replace("DTSTART:", "").strip()
            elif line.startswith("DTEND:"):
                current_event["End Date"] = line.replace("DTEND:", "").strip()
            elif line.startswith("SUMMARY:"):
                current_event["Summary"] = line.replace("SUMMARY:", "").strip()
            elif line.startswith("DESCRIPTION:"):
                current_event["Description"] = line.replace("DESCRIPTION:", "").strip()
            elif line.startswith("LOCATION:"):
                current_event["Location"] = line.replace("LOCATION:", "").strip()
    return events

# Fonction pour traiter tous les fichiers ICS dans un dossier
def process_ics_folder(folder_path):
    all_events = []
    for filename in os.listdir(folder_path):
        if filename.endswith(".ics"):
            file_path = os.path.join(folder_path, filename)
            events = parse_ics_file(file_path)
            all_events.extend(events)
    return all_events

# Extraction des événements depuis le dossier
events = process_ics_folder(folder_path)

# Conversion des données en tableau avec pandas
if events:
    df = pd.DataFrame(events)
    print("Voici les événements extraits :")
    print(df.to_string(index=False))
    
    # Sauvegarder les événements dans un fichier CSV
    output_csv = os.path.join(folder_path, "events_output.csv")
    df.to_csv(output_csv, index=False, encoding='utf-8')
    print(f"\nLes événements ont été sauvegardés dans : {output_csv}")
else:
    print("Aucun événement trouvé dans les fichiers ICS.")
