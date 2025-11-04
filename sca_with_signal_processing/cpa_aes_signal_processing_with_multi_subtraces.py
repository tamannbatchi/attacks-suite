import numpy as np
from scipy.signal import butter, filtfilt, find_peaks
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt

# Simulation de 50 traces de 3000 points
n_traces = 50
n_points = 3000
np.random.seed(42)

# Traces bruitées + plusieurs pics simulés
traces = np.random.normal(0, 0.01, (n_traces, n_points))
for i in range(n_traces):
    for j in range(3):  # 3 pics par trace
        pos = 1000 + j * 500
        traces[i, pos-10:pos+10] += np.random.normal(0.05, 0.01)

# Modèle de fuite simulé (ex. poids Hamming)
modele_fuite = np.random.randint(0, 9, n_traces)


# Filtrage passe bas
def filtrer_traces(traces, cutoff=0.05):
    b, a = butter(N=4, Wn=cutoff)
    return np.array([filtfilt(b, a, trace) for trace in traces])

traces_filtrees = filtrer_traces(traces)


# Détection de plusieurs pics
def detecter_pics(trace, seuil=0.02):
    indices, _ = find_peaks(trace, height=np.mean(trace) + seuil)
    return indices

pics_multi = [detecter_pics(trace) for trace in traces_filtrees]


# Extraction de plusieurs fenêtres par trace
def extraire_multi_fenetres(traces, pics_multi, window_size=50):
    fenetres = []
    for i, trace_pics in enumerate(pics_multi):
        for idx in trace_pics:
            debut = max(0, idx - window_size)
            fin = min(len(traces[i]), idx + window_size)
            sous_trace = np.zeros(2 * window_size)
            sous_trace[:fin - debut] = traces[i][debut:fin]
            fenetres.append(sous_trace)
    return np.array(fenetres)

fenetres = extraire_multi_fenetres(traces_filtrees, pics_multi)


# Normalisation
scaler = StandardScaler()
fenetres_norm = scaler.fit_transform(fenetres)


# PCA (Réduction du bruit)
pca = PCA(n_components=10)
fenetres_pca = pca.fit_transform(fenetres_norm)

print(f"Variance expliquée : {np.sum(pca.explained_variance_ratio_):.2%}")


# Attaque CPA sur les fenêtres normalisées
def attaque_cpa(traces, modele_fuite):
    traces_centre = traces - np.mean(traces, axis=0)
    modele_centre = modele_fuite - np.mean(modele_fuite)
    numerateur = np.dot(traces_centre.T, modele_centre)
    denominateur = np.std(traces, axis=0) * np.std(modele_fuite)
    return numerateur / denominateur

# On adapte modele_fuite à la taille de fenetres
modele_fuite_exp = np.tile(modele_fuite, 3)  # 3 pics par trace

correlations = attaque_cpa(fenetres_norm, modele_fuite_exp)

plt.plot(correlations)
plt.title("CPA sur fenêtres multiples")
plt.xlabel("Point temporel")
plt.ylabel("Corrélation")
plt.grid(True)
plt.show()

