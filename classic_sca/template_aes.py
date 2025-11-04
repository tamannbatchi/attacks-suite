import numpy as np
import matplotlib.pyplot as plt

# Définir une S-box simplifiée : Sbox[i] = i^2 % 256
Sbox = np.array([(i**2) % 256 for i in range(256)])

# Choisir une valeur réelle de Sbox(P ⊕ K)
true_plaintext = 0x55
true_key = 0x0A
true_value = Sbox[true_plaintext ^ true_key]

# Phase de profilage : créer des templates pour chaque valeur possible
templates = {}
for v in range(256):
    # Simuler 10 traces pour chaque valeur v
    traces = np.random.normal(loc=v/255, scale=0.02, size=(10, 3))  # 3 points par trace
    mu = np.mean(traces, axis=0)  # Moyenne des 10 traces
    cov = np.cov(traces, rowvar=False)  # Matrice de covariance
    templates[v] = (mu, cov)  # Stocker le template

# Générer une trace cible correspondant à la vraie valeur
target_trace = np.random.normal(loc=true_value/255, scale=0.02, size=3)

# Calculer les scores (distance de Mahalanobis) pour chaque hypothèse
scores = []
for v in range(256):
    mu, cov = templates[v]
    try:
        inv_cov = np.linalg.inv(cov)
        diff = target_trace - mu
        score = np.exp(-0.5 * diff @ inv_cov @ diff.T)  # Score gaussien
    except np.linalg.LinAlgError:
        score = 0  # Si covariance non inversible
    scores.append(score)

# Identifier la meilleure hypothèse
best_guess = np.argmax(scores)
print(f"Valeur estimée : {best_guess}, vraie valeur : {true_value}")

# Tracer les scores
plt.figure(figsize=(10, 4))
plt.plot(scores, label="Score par hypothèse")
plt.axvline(true_value, color='r', linestyle='--', label="Vraie valeur")
plt.axvline(best_guess, color='g', linestyle='--', label="Hypothèse max")
plt.title("Attaque template sur AES")
plt.xlabel("Hypothèse de Sbox(P ⊕ K)")
plt.ylabel("Score de probabilité")
plt.legend()
plt.grid(True)
plt.show()
