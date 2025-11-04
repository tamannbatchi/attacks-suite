import numpy as np

# Simuler 5 plaintexts
plaintexts = np.array([0x00, 0x01, 0x02, 0x03, 0x04])
true_key = 0x2A

# Traces simulées avec masquage
T1 = np.array([0.3, 0.4, 0.2, 0.5, 0.3])  # Sbox masquée
T2 = np.array([0.6, 0.7, 0.5, 0.8, 0.6])  # démasquage

# Fonction combinée
combined = T1 * T2

# Modèle théorique
def hamming_weight(x): return bin(x).count('1')
model = np.array([hamming_weight(p ^ true_key) for p in plaintexts])

# Corrélation
corr = np.corrcoef(model, combined)[0, 1]
print(f"Corrélation d’ordre 2 : {corr:.3f}")
