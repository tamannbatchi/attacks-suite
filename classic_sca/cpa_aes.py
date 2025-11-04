import numpy as np

# S-box AES
SBOX = [99,124,119,123,242,107,111,197,...]  # tronquée pour lisibilité

# Simuler des plaintexts et des traces
plaintexts = np.array([0x00, 0x01, 0x02, 0x03, 0x04])
true_key = 0x2A
traces = np.array([
    [0.3, 0.5, 0.7],  # trace 1
    [0.4, 0.6, 0.8],  # trace 2
    [0.2, 0.4, 0.6],  # trace 3
    [0.5, 0.7, 0.9],  # trace 4
    [0.3, 0.5, 0.7],  # trace 5
])

# Fonction poids de Hamming
def hamming_weight(x):
    return bin(x).count('1')

# Attaque CPA
best_corr = -1
best_guess = None
for guess in range(256):
    model = [hamming_weight(SBOX[p ^ guess]) for p in plaintexts]   #Hamming weight vector
    model = np.array(model)   #Convert to array
    for t in range(traces.shape[1]):
        corr = np.corrcoef(model, traces[:, t])[0, 1]  
        if abs(corr) > best_corr:
            best_corr = abs(corr)
            best_guess = guess

print(f"Clé retrouvée : 0x{best_guess:02X} avec corrélation {best_corr:.3f}")
