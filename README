📚 Simple Local Password Manager in C

Description :
Ce projet est un gestionnaire de mots de passe local éducatif écrit en C utilisant libsodium pour le chiffrement et Argon2id pour le hachage. Il permet de stocker et lister des mots de passe protégés par un mot de passe maître.

⚠️ Attention : Ce projet est uniquement pédagogique. Il n’est pas conçu pour un usage réel.
Ne stockez jamais vos mots de passe réels ici.

🔹 Fonctionnalités

Crée et vérifie un mot de passe maître.

Stocke les mots de passe par service dans un fichier chiffré.

Affiche la liste des secrets après déchiffrement.

Analyse et génère des mots de passe pour vérifier leur robustesse.

Utilise Argon2id (MODERATE) et crypto_secretbox pour sécuriser les données.

🔹 Comment l’utiliser

Compiler le programme :

gcc -o password_manager password_manager.c -lsodium

Lancer l’application :

./password_manager

Suivre le menu pour :

Lister les secrets

Ajouter un secret

Analyser ou générer un mot de passe

🔹 Limitations connues

La saisie du mot de passe maître n’est pas masquée à l’écran.

La longueur des mots de passe est actuellement limitée à 30 caractères.

Les structures sont écrites dans le fichier binaire directement (non portable).

Pas de protection contre la corruption du fichier .vault.bin.

Les données sont stockées localement sans verrouillage mémoire, donc vulnérables si l’ordinateur est compromis.

🔹 Bonnes pratiques pédagogiques

Pour sécuriser vraiment le mot de passe maître, utiliser getpass() pour masquer l’entrée.

Pour supprimer la limite des mots de passe, utiliser une allocation dynamique.

Pour production : chiffrer tout le fichier et ajouter un HMAC global.

🔹 Installation de libsodium (Linux/macOS)
sudo apt install libsodium-dev       # Ubuntu/Debian
brew install libsodium               # macOS
🔹 Licence

Ce projet est open-source à titre éducatif.
Pas de garantie de sécurité pour usage réel.
