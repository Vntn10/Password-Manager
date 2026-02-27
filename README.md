# 🔐 Simple Local Password Manager in C

![Language](https://img.shields.io/badge/Language-C-blue.svg)
![Security](https://img.shields.io/badge/Security-libsodium-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey.svg)

## 📝 Description
Ce projet est un **gestionnaire de mots de passe local éducatif**. Il utilise la bibliothèque **libsodium** pour implémenter des standards de cryptographie modernes comme **Argon2id** (hachage) et **XSalsa20-Poly1305** (chiffrement).

> [!CAUTION]
> **Projet pédagogique uniquement.** Ce programme n'est pas conçu pour un usage réel en production. Ne stockez jamais vos mots de passe personnels ici.

---

## ✨ Fonctionnalités
* **Authentification Maître** : Création et vérification d'un mot de passe principal via Argon2id.
* **Coffre-fort Chiffré** : Stockage binaire des secrets par service.
* **Lecture Sécurisée** : Déchiffrement à la volée pour lister vos comptes.
* **Outils de Robustesse** : Analyse de complexité et générateur de mots de passe aléatoires sécurisés.
* **Gestion Mémoire** : Utilisation de `sodium_memzero` pour effacer les données sensibles de la RAM.



---

## 🛠️ Installation & Utilisation

### 1. Prérequis (Installation de libsodium)
```bash
# Ubuntu / Debian
sudo apt install libsodium-dev

# macOS
brew install libsodium
```

### 2. Compilation
```Bash

gcc -o password_manager password_manager.c -lsodium
```
### 3. Lancer l'application
```Bash

./password_manager

```

## ⚠️ Limitations connues
* **Saisie en clair** : Le mot de passe maître s'affiche dans le terminal lors de la saisie.
* **Taille fixe** : Mots de passe limités à 30 caractères (Buffer fixe).
* **Portabilité** : Écriture directe de structures C en binaire (dépend de l'architecture).
* **Sécurité OS** : Pas de verrouillage de la mémoire (mlock), données potentiellement vulnérables au swap.

🎓 Axes d'amélioration (Pédagogie)

* **Utiliser getpass() ou termios.h pour masquer la saisie utilisateur.

* **Passer à une allocation dynamique (malloc) pour gérer des secrets de tailles illimitées.

* **Ajouter un HMAC global pour vérifier l'intégrité totale du fichier .vault.bin.

📄 Licence

Ce projet est open-source à titre éducatif. Aucune garantie de sécurité n'est fournie pour un usage réel.
