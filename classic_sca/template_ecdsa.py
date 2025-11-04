import numpy as np
import matplotlib.pyplot as plt

# Cibler le bit 3 du nonce
true_bit = 1  # Valeur réelle du bit

# Phase de profilage : créer deux classes
templates = {}
for bit_value in [0, 1]:
    # Simuler 10 traces pour chaque bit
    traces = np.random.normal(loc=0.3 + 0.5 * bit_value, scale=0.02, size=(10, 3))
    mu = np.mean(traces, axis=0)
    cov = np.cov(traces, rowvar=False)
    templates[bit_value] = (mu, cov)

# Générer une trace cible correspondant au vrai bit
target_trace = np.random.normal(loc=0.3 + 0.5 * true_bit, scale=0.02, size=3)

# Calculer les scores pour bit = 0 et bit = 1
scores = []
for bit_value in [0, 1]:
    mu, cov = templates[bit_value]
    try:
        inv_cov = np.linalg.inv(cov)
        diff = target_trace - mu
        score = np.exp(-0.5 * diff @ inv_cov @ diff.T)
    except np.linalg.LinAlgError:
        score = 0
    scores.append(score)

# Prédiction
predicted_bit = np.argmax(scores)
print(f"Bit estimé : {predicted_bit}, vrai bit : {true_bit}")

# Tracer les scores
plt.bar(["bit=0", "bit=1"], scores, color=["blue", "orange"])
plt.title("Attaque template sur ECDSA (bit du nonce)")
plt.ylabel("Score de probabilité")
plt.grid(True)
plt.show()
