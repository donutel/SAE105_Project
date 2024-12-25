import matplotlib.pyplot as plt

# Données (remplacez-les par vos propres données)
emplacements = ['G_012', 'D_110', 'G_004', 'G_019', 'D_032', 'D_026', 'G_007', 'G_024', 'G_003', 'G_002', 'G_011', 'AMPH1', 'G_010', 'G_016', 'G_014']
nombre_evenements = [100, 95, 90, 80, 75, 70, 60, 50, 40, 30, 20, 15, 10, 5, 2]

# Création du graphique
plt.figure(figsize=(12, 6))
bars = plt.bar(emplacements, nombre_evenements, color='skyblue', edgecolor='black', linewidth=1.2)

# Améliorations esthétiques
plt.title("Nombre d'événements par emplacement", fontsize=16, fontweight='bold')
plt.xlabel("Emplacement", fontsize=12)
plt.ylabel("Nombre d'événements", fontsize=12)

# Rotation des étiquettes
plt.xticks(rotation=45, ha='right', fontsize=10)

# Ajout des valeurs au-dessus des barres
for bar in bars:
    yval = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2, yval + 1, int(yval), ha='center', va='bottom', fontsize=10, color='black')

# Grille pour faciliter la lecture
plt.grid(axis='y', linestyle='--', alpha=0.7)

# Afficher le graphique
plt.tight_layout()
plt.show()
