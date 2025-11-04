import numpy as np

# Nonce secret (8 bits pour simplifier)
k_true = [1,0,1,0,1,0,1,0]
# Traces simulées
traces = np.array([
    [0.82, 0.28, 0.79, 0.31, 0.85, 0.29, 0.75, 0.33],
    [0.81, 0.32, 0.77, 0.30, 0.83, 0.27, 0.74, 0.34],
    [0.80, 0.31, 0.78, 0.29, 0.84, 0.28, 0.76, 0.32],
])

# Modèle théorique : 1 → 0.8, 0 → 0.3
def model_for_bit(bit):
    return 0.8 if bit == 1 else 0.3

# CPA sur chaque bit
k_recovered = []
for i in range(traces.shape[1]):
    best_corr = -1
    best_bit = None
    for bit_guess in [0, 1]:
        model = np.array([model_for_bit(bit_guess)] * traces.shape[0])
        corr = np.corrcoef(model, traces[:, i])[0, 1]
        if abs(corr) > best_corr:
            best_corr = abs(corr)
            best_bit = bit_guess
    k_recovered.append(best_bit)

print("Bits extraits de k :", k_recovered)

# Récupération de d
s, r, h = 0xC1, 0xA7, 0xAB
k_val = int("".join(map(str, k_recovered)), 2)
r_inv = pow(r, -1, 256)
d = ((s * k_val - h) * r_inv) % 256
print(f"Clé privée estimée : {d}")
