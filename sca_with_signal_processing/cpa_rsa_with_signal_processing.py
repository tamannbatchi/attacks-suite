import numpy as np
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from scipy.signal import butter, filtfilt


np.random.seed(0)

# Simulation de 5 traces RSA de 3000 points chacune
n_traces = 5
n_points = 3000
traces = []

# Clé privée simulée : 8 bits
cle_privee = np.array([1, 0, 1, 1, 0, 0, 1, 0])

# Chaque bit de la clé déclenche une opération (square ou square+multiply)
for i in range(n_traces):
    trace = np.random.normal(0, 0.01, n_points)
    for j, bit in enumerate(cle_privee):
        pos = 300 + j * 300
        if bit == 1:
            trace[pos:pos+50] += 0.05  # square + multiply
        else:
            trace[pos:pos+50] += 0.02  # square only
    traces.append(trace)

traces = np.array(traces)


# Filtrage passe-bas
def filtrer(trace, cutoff=0.05):
    b, a = butter(N=4, Wn=cutoff)
    return filtfilt(b, a, trace)

traces_filtrees = np.array([filtrer(t) for t in traces])

# Segmentation par opération
# On découpe chaque trace en 8 segments de 300 points (1 par bit de clé)
segments = []
for trace in traces_filtrees:
    segs = [trace[i*300:(i+1)*300] for i in range(8)]
    segments.append(segs)

segments = np.array(segments)  # shape: (5 traces, 8 segments, 300 points)

# Normalisation
segments_reshaped = segments.reshape(-1, 300)  # 40 segments au total
scaler = StandardScaler()
segments_norm = scaler.fit_transform(segments_reshaped)

# PCA (Réduction du bruit)

pca = PCA(n_components=5)
segments_pca = pca.fit_transform(segments_norm)

# Attaque CPA

# Modèle de fuite : 1 si bit de clé = 1, 0 sinon (répété pour chaque trace)
modele_fuite = np.tile(cle_privee, n_traces)

def attaque_cpa(traces, modele):
    traces_centre = traces - np.mean(traces, axis=0)
    modele_centre = modele - np.mean(modele)
    numerateur = np.dot(traces_centre.T, modele_centre)
    denominateur = np.std(traces, axis=0) * np.std(modele)
    return numerateur / denominateur

correlations = attaque_cpa(segments_pca, modele_fuite)


# Identification des bits de la clé
print("Corrélations CPA par composante PCA :")
for i, c in enumerate(correlations):
    print(f"Composante {i+1} : {c:.4f}")

