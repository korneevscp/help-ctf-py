# ⌁ Sentinelle — Analyse réseau

Analyseur heuristique de captures Wireshark (`.pcap` / `.pcapng`). Sentinelle extrait les flux via **tshark**, applique un jeu de règles de détection et met en évidence les adresses IP liées à des comportements suspects.

Utilisable en **interface web locale** (Flask) ou en **ligne de commande**.

> Les résultats sont heuristiques : une alerte signale un comportement à vérifier, pas une compromission confirmée. TLS n'est pas déchiffré.

---

## Fonctionnalités

| Règle | Sévérité | Détection |
|---|---|---|
| `SCAN_PORTS` | ÉLEVÉ | Une source tente des connexions TCP (SYN) vers de nombreux ports d'un même hôte |
| `SCAN_HORIZONTAL` | MOYEN | Une source sonde le même port sur de nombreux hôtes |
| `SYN_FLOOD` | ÉLEVÉ / MOYEN | Volume anormal de SYN, avec taux de SYN-ACK en retour |
| `DNS_VOLUME` | MOYEN | Nombre élevé de requêtes DNS émises par une source |
| `DNS_TUNNEL` | ÉLEVÉ | Sous-domaines longs ou volumineux (exfiltration / tunnel DNS) |
| `PORT_INHABITUEL` | ÉLEVÉ / MOYEN | Trafic soutenu sur un port non standard, ou sur un port réputé malveillant (4444, 1337, 31337, 6667…) |
| `CLAIR` | MOYEN / INFO | Sessions en clair : Telnet, FTP, POP3, IMAP, TFTP |

Les alertes « protocole en clair » produites par un scan sont automatiquement filtrées.

---

## Prérequis

- Python **3.9+**
- **Wireshark** avec **tshark** (coché par défaut à l'installation)
- Flask

```bash
pip install -r requirements.txt
```

Sentinelle cherche tshark dans cet ordre :

1. l'option `--tshark` (CLI)
2. la variable d'environnement `TSHARK_PATH`
3. le `PATH`
4. `C:\Program Files\Wireshark\tshark.exe`
5. `/Applications/Wireshark.app/Contents/MacOS/tshark`

```bat
set TSHARK_PATH=D:\Outils\Wireshark\tshark.exe
```

---

## Utilisation

### Interface web

```bash
py app.py
```

Ouvrir <http://127.0.0.1:5000>, déposer la capture (300 Mo max) et lancer l'analyse.

Port personnalisé :

```bat
set PORT=8080
py app.py
```

Le serveur écoute uniquement sur `127.0.0.1`. La capture est stockée dans un dossier temporaire puis supprimée après l'analyse.

### Ligne de commande

```bash
py sentinelle.py capture.pcapng
```

```bash
py sentinelle.py capture.pcapng --port-scan-threshold 10 --dns-chars-threshold 300
```

| Option | Défaut | Rôle |
|---|---|---|
| `--tshark` | auto | Chemin de tshark |
| `--timeout` | 300 | Délai max de tshark (s) |
| `--port-scan-threshold` | 20 | Ports / hôtes distincts pour déclencher un scan |
| `--syn-threshold` | 100 | SYN par couple source → destination |
| `--dns-threshold` | 100 | Requêtes DNS par source |
| `--dns-chars-threshold` | 500 | Caractères cumulés dans les sous-domaines d'un domaine |
| `--unusual-port-threshold` | 50 | Paquets sur un port non standard |

Exemple de sortie :

```
Paquets IP : 55 | Flux : 41 | Alertes : 3
Période UTC : 2026-11-14 21:21:37 -> 2026-11-14 21:21:37

[ÉLEVÉ] DNS_TUNNEL — Possible exfiltration / tunnel DNS
    10.0.0.7 a encodé 695 caractères dans des sous-domaines de evil.com sur 15 requêtes.
    source: 10.0.0.7 · destination: 8.8.8.8 · domaine: evil.com · caracteres: 695 · ...

[ÉLEVÉ] SCAN_PORTS — Scan de ports vertical
    10.0.0.5 a tenté d'ouvrir des connexions TCP vers 39 ports distincts de 10.0.0.9.
```

Code retour : `0` si l'analyse aboutit, `1` en cas d'erreur (tshark absent, fichier introuvable…).

---

## Tests

```bash
py -m unittest discover -s tests -v
```

Les tests couvrent :

- **Unitaires** : parsing des lignes tshark (IPv4/IPv6, formats `1/0` et `True/False`), chaque règle de détection, tri par sévérité, résumé
- **Intégration** : chaîne complète `analyze()` avec un tshark simulé
- **Application** : routes Flask (GET, extension refusée, rendu du rapport, affichage des erreurs)

Aucun tshark réel n'est requis pour lancer les tests.

---

## Structure

```
sentinel wireshark/
├── app.py                 Interface web Flask
├── sentinelle.py          Moteur : extraction tshark + règles + CLI
├── requirements.txt
├── README.md
└── tests/
    └── test_sentinelle.py
```

### Utiliser le moteur en Python

```python
import argparse
from sentinelle import analyze

args = argparse.Namespace(tshark=None, timeout=300, port_scan_threshold=20,
                          syn_threshold=100, dns_threshold=100,
                          dns_chars_threshold=500, unusual_port_threshold=50)

findings, summary = analyze("capture.pcapng", args)

for f in findings:
    print(f.severity, f.rule, f.evidence)
```

---

## Avertissement

Outil destiné à l'analyse de **vos propres captures** ou de captures obtenues dans un cadre autorisé (CTF, lab, audit contractualisé). Les fichiers PCAP peuvent contenir des données sensibles : manipulez-les avec précaution.
