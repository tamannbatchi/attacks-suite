import numpy as np

# Nonce secret (8 bits)
k_true = [1,0,1,0,1,0,1,0]

# Traces simulées : T1 et T2 sont indépendants
T1 = np.array([
    [0.8, 0.3, 0.75, 0.28, 0.82, 0.29, 0.78, 0.31],
    [0.79, 0.32, 0.76, 0.30, 0.81, 0.27, 0.77, 0.33],
])
T2 = np.array([
    [0.6, 0.4, 0.65, 0.38, 0.62, 0.39, 0.68, 0.41],
    [0.61, 0.42, 0.66, 0.40, 0.63, 0.37, 0.67, 0.43],
])

# Combinaison d’ordre 2
combined = T1 * T2  # shape (2, 8)

# Hypothèse sur bit de k
def model_for_bit(bit): 
    return 0.8 if bit == 1 else 0.3

# Corrélation sur chaque bit
k_recovered = []
for i in range(combined.shape[1]):
    best_corr = -1
    best_bit = None
    for bit_guess in [0, 1]:
        model = np.array([model_for_bit(bit_guess)] * combined.shape[0])
        corr = np.corrcoef(model, combined[:, i])[0, 1]
        if abs(corr) > best_corr:
            best_corr = abs(corr)
            best_bit = bit_guess
    k_recovered.append(best_bit)

print("Bits extraits de k :", k_recovered)
