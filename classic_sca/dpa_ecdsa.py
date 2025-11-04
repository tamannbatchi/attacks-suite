import numpy as np

# Nonce secret (8 bits pour simplifier)
k_true = [1,0,1,0,1,0,1,0]
# Traces simulées : 1 → 0.8, 0 → 0.3 + bruit
traces = np.array([
    [0.82, 0.28, 0.79, 0.31, 0.85, 0.29, 0.75, 0.33],
    [0.81, 0.32, 0.77, 0.30, 0.83, 0.27, 0.74, 0.34],
    [0.80, 0.31, 0.78, 0.29, 0.84, 0.28, 0.76, 0.32],
])

# Seuil pour distinguer les bits
threshold = 0.5
k_recovered = []
for i in range(traces.shape[1]):
    avg = np.mean(traces[:, i])
    bit = 1 if avg > threshold else 0
    k_recovered.append(bit)

print("Bits extraits de k :", k_recovered)

# Exemple de récupération de d
s, r, h = 0xC1, 0xA7, 0xAB
k_val = int("".join(map(str, k_recovered)), 2)
r_inv = pow(r, -1, 256)
d = ((s * k_val - h) * r_inv) % 256
print(f"Clé privée estimée : {d}")
