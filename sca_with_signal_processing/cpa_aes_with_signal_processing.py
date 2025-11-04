import numpy as np
import matplotlib.pyplot as plt
from scipy.signal import butter, filtfilt, find_peaks
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler


# Simulation de 50 traces de 3000 points chacune
n_traces = 50
n_points = 3000
np.random.seed(42)  # graine aléatoire pour avoir des résultats reproductibles

# Traces simulées : bruit + pic autour du point 1500
traces = np.random.normal(0, 0.01, (n_traces, n_points))
for i in range(n_traces):
    traces[i, 1490:1510] += np.random.normal(0.05, 0.01)  # pic simulé

# Hypothèse de clé : poids Hamming simulé
modele_fuite = np.random.randint(0, 9, n_traces)

# Filtrage passe bas
def filtrer_traces(traces, cutoff=0.05):
    b, a = butter(N=4, Wn=cutoff)  # crée un filtre passe bas d'ordre 4 avec une fréquence de coupure normalisée à 0.05
    return np.array([filtfilt(b, a, trace) for trace in traces])

# Traces filtrées prêtes pour l'analyse
traces_filtrees = filtrer_traces(traces)

# Détection des pics pour alignement
def detecter_pic(trace, seuil=0.02):
    indices, _ = find_peaks(trace, height=np.mean(trace) + seuil)  # Pics dont l'amplitude dépasse moyenne + seuil
    return indices[0] if len(indices) > 0 else None     # Retourne le premier pic détecté

# Trouver le pic principal dans chaque trace
pics = [detecter_pic(trace) for trace in traces_filtrees]


# Extraction de sous-traces alignées
def extraire_sous_traces(traces, pics, window_size=50):
    sous_traces = []

# Pour chaque trace, on extrait une fenêtre de 100 points centrée sur le pic
# Si la fenêtre dépasse les bornes, on complète par des zéros
    for i, idx in enumerate(pics):
        if idx is None:
            continue
        debut = max(0, idx - window_size)
        fin = min(len(traces[i]), idx + window_size)
        trace = np.zeros(2 * window_size)
        trace[:fin - debut] = traces[i][debut:fin]
        sous_traces.append(trace)

# Retourne un tableau de sous-traces alignées
    return np.array(sous_traces)

# Extraction des sous-traces à partir des traces filtrées
sous_traces = extraire_sous_traces(traces_filtrees, pics)

# Normalisation : on centre et réduit chaque colonne (point temporel) pour que moyenne = 0 et écart-type = 1
# pour éviter que certains points dominent la CPA à cause de leur amplitude
scaler = StandardScaler()
sous_traces_norm = scaler.fit_transform(sous_traces)

# PCA (Réduction de dimension) : on réduit les sous-traces à dix dimensions principales
# pour visualiser les données, réduire le bruit et accélérer l'attaque CPA
pca = PCA(n_components=10)
sous_traces_pca = pca.fit_transform(sous_traces_norm)

print(f"Variance expliquée par les 10 composantes : {np.sum(pca.explained_variance_ratio_):.2%}")


# Analyse fréquentielle
fft = np.fft.fft(sous_traces_pca[0])    # Transformée de Fourier de la première sous-trace
freq = np.fft.fftfreq(len(fft), d=1/100e6)     # Génération des fréquences associées (échantillonage à 100MHz)

# Affichage du spectre de fréquence (partie positive uniquement)
plt.plot(freq[:len(freq)//2], np.abs(fft)[:len(freq)//2])
plt.title("Spectre de fréquence de la première sous-trace")
plt.xlabel("Fréquence (Hz)")
plt.ylabel("Amplitude")
plt.grid(True)
plt.show()

# Attaque CPA
def attaque_cpa(sous_traces, modele_fuite):

# On centre les sous-traces et le modèle de fuite
    sous_traces_centre = sous_traces - np.mean(sous_traces, axis=0)
    modele_centre = modele_fuite - np.mean(modele_fuite)

# Calcul de la corrélation entre chaque point temporel et le modèle
    numerateur = np.dot(sous_traces_centre.T, modele_centre)
    denominateur = np.std(sous_traces, axis=0) * np.std(modele_fuite)

# Retourne un vecteur de corrélation
    return numerateur / denominateur

# Application de l'attaque CPA sur nos sous-traces et notre modèle de fuite
correlations = attaque_cpa(sous_traces_norm, modele_fuite)

# Affichage du score de corrélation pour chaque point, le pic indique le point de fuite
plt.plot(correlations)
plt.title("Corrélation CPA")
plt.xlabel("Point temporel")
plt.ylabel("Corrélation")
plt.grid(True)
plt.show()

