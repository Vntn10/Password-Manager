#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <sodium.h> // Utilisation de libsodium pour la cryptographie

#define MAXCAR 31
#define HASH_FILE ".master.hash"
#define VAULT_FILE ".vault.bin"

/**
 * Structure stockant une entrée de mot de passe chiffrée.
 */
typedef struct {
    char service[50];
    unsigned char encrypted_password[MAXCAR + crypto_secretbox_MACBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES]; // Vecteur d'initialisation unique
    size_t cipher_len;
} PasswordEntry;

/**
 * Structure pour stocker le hash du mot de passe maître ET le sel de dérivation.
 */
typedef struct {
    char hash[crypto_pwhash_STRBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
} MasterData;

// --- PROTOTYPES ---
int analysepasswd(const char *password, int *min, int *maj, int *num, int *sym);
int scorepwd(int len, int min, int maj, int num, int sym);
void genererpasswd(char *password, int longueur);
void save_master_data(MasterData *data);
int load_master_data(MasterData *data);
void ajouter_secret(const char *master, const unsigned char *salt, const char *service, const char *pwd_to_hide);
void lister_secrets(const char *master, const unsigned char *salt);

// --- FONCTIONS DE PERSISTENCE ---

/**
 * Sauvegarde les données d'authentification maître dans un fichier binaire.
 */
void save_master_data(MasterData *data) {
    FILE *f = fopen(HASH_FILE, "wb");
    if (f) {
        fwrite(data, sizeof(MasterData), 1, f);
        fclose(f);
    }
}

/**
 * Charge les données d'authentification maître.
 * @return 1 si succès, 0 si le fichier n'existe pas.
 */
int load_master_data(MasterData *data) {
    FILE *f = fopen(HASH_FILE, "rb");
    if (!f) return 0;
    size_t read = fread(data, sizeof(MasterData), 1, f);
    fclose(f);
    return (read == 1);
}

/**
 * Dérive une clé de chiffrement à partir du mot de passe maître et du sel.
 * Utilise l'algorithme Argon2id.
 */
int derive_key(unsigned char *key, const char *master, const unsigned char *salt) {
    return crypto_pwhash(key, crypto_secretbox_KEYBYTES, master, strlen(master), salt,
                         crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE,
                         crypto_pwhash_ALG_ARGON2ID13);
}

// --- FONCTIONS DE GESTION DES SECRETS ---

/**
 * Chiffre et ajoute un nouveau secret dans le coffre-fort.
 */
void ajouter_secret(const char *master, const unsigned char *salt, const char *service, const char *pwd_to_hide) {
    unsigned char key[crypto_secretbox_KEYBYTES];
    
    // Dérivation de la clé de session
    if (derive_key(key, master, salt) != 0) return;

    PasswordEntry entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.service, service, 49);
    
    // Génération d'un nonce unique pour ce secret précis
    randombytes_buf(entry.nonce, sizeof entry.nonce);
    
    // Chiffrement symétrique
    crypto_secretbox_easy(entry.encrypted_password, (const unsigned char *)pwd_to_hide, 
                          strlen(pwd_to_hide), entry.nonce, key);
    entry.cipher_len = strlen(pwd_to_hide) + crypto_secretbox_MACBYTES;

    // Ajout à la fin du fichier (mode "append")
    FILE *f = fopen(VAULT_FILE, "ab");
    if (f) { 
        fwrite(&entry, sizeof(PasswordEntry), 1, f); 
        fclose(f); 
    }
    
    // Sécurité : effacer la clé de la mémoire vive
    sodium_memzero(key, sizeof key);
    printf("\n[OK] Mot de passe pour %s enregistré.\n", service);
}

/**
 * Parcourt le coffre-fort, déchiffre et affiche les secrets.
 */
void lister_secrets(const char *master, const unsigned char *salt) {
    unsigned char key[crypto_secretbox_KEYBYTES];
    if (derive_key(key, master, salt) != 0) return;

    FILE *f = fopen(VAULT_FILE, "rb");
    if (!f) { 
        printf("\nAucun secret enregistré.\n"); 
        sodium_memzero(key, sizeof key);
        return; 
    }

    PasswordEntry entry;
    printf("\n--- VOS MOTS DE PASSE ---\n");
    while (fread(&entry, sizeof(PasswordEntry), 1, f)) {
        unsigned char decrypted[MAXCAR + 1];
        
        // Tentative de déchiffrement
        if (crypto_secretbox_open_easy(decrypted, entry.encrypted_password, entry.cipher_len, 
                                       entry.nonce, key) == 0) {
            decrypted[entry.cipher_len - crypto_secretbox_MACBYTES] = '\0';
            printf("Service: %-15s | Password: %s\n", entry.service, decrypted);
        } else {
            printf("Erreur de déchiffrement pour %s (Clé incorrecte ?)\n", entry.service);
        }
    }
    fclose(f);
    sodium_memzero(key, sizeof key);
}

// --- LOGIQUE D'ANALYSE ET GÉNÉRATION ---

/**
 * Analyse la complexité d'une chaîne de caractères.
 */
int analysepasswd(const char *password, int *minuscules, int *majuscules, int *nbchiffres, int *nbsymboles) {
    *minuscules = *majuscules = *nbchiffres = *nbsymboles = 0;
    int len = strlen(password);
    for (int i = 0; i < len; i++) {
        if (islower(password[i])) (*minuscules)++;
        else if (isupper(password[i])) (*majuscules)++;
        else if (isdigit(password[i])) (*nbchiffres)++;
        else (*nbsymboles)++;
    }
    return len;
}

/**
 * Calcule un score de force sur 100.
 */
int scorepwd(int longueur, int min, int maj, int chiffres, int sym) {
    int score = 0;
    if (longueur >= 12) score += 40;
    if (min) score += 15;
    if (maj) score += 15;
    if (chiffres) score += 15;
    if (sym) score += 15;
    return (score > 100) ? 100 : score;
}

/**
 * Génère un mot de passe aléatoire sécurisé via libsodium.
 */
void genererpasswd(char *password, int longueur) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*?";
    for (int i = 0; i < longueur; i++) {
        password[i] = charset[randombytes_uniform(sizeof(charset) - 1)];
    }
    password[longueur] = '\0';
}

// --- POINT D'ENTRÉE ---

int main() {
    // Initialisation obligatoire de la bibliothèque de sécurité
    if (sodium_init() < 0) return 1;

    char master_pwd[100];
    MasterData m_data;

    // --- PHASE D'AUTHENTIFICATION ---
    if (!load_master_data(&m_data)) {
        printf("Configuration : Créez un mot de passe maître : ");
        scanf("%99s", master_pwd);
        
        // Initialisation du nouveau coffre-fort
        randombytes_buf(m_data.salt, sizeof(m_data.salt));
        
        // Hachage du mot de passe maître (pour vérification ultérieure)
        crypto_pwhash_str(m_data.hash, master_pwd, strlen(master_pwd), 
                          crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE);
        
        save_master_data(&m_data);
        printf("Initialisation terminée. Sel généré et sauvegardé.\n");
    } else {
        printf("Mot de passe maître : ");
        scanf("%99s", master_pwd);

        // Vérification du mot de passe maître contre le hash stocké
        if (crypto_pwhash_str_verify(m_data.hash, master_pwd, strlen(master_pwd)) != 0) {
            printf("Accès refusé.\n");
            sodium_memzero(master_pwd, sizeof(master_pwd));
            return 1;
        }
    }

    // --- MENU PRINCIPAL ---
    int choix = 0;
    while (choix != 4) {
        printf("\n1. Lister les secrets\n2. Ajouter un secret\n3. Analyser/Générer\n4. Quitter\nChoix : ");
        if (scanf("%d", &choix) != 1) break;
        getchar(); // Nettoyer le buffer

        if (choix == 1) {
            lister_secrets(master_pwd, m_data.salt);
        }
        else if (choix == 2) {
            char srv[50], p[MAXCAR];
            printf("Service : "); scanf("%49s", srv);
            printf("MDP : "); scanf("%30s", p);
            ajouter_secret(master_pwd, m_data.salt, srv, p);
            sodium_memzero(p, sizeof(p)); // Nettoyage
        }
        else if (choix == 3) {
            char p[MAXCAR];
            printf("Entrez un mdp ou 'gen' : ");
            scanf("%30s", p);
            if(strcmp(p, "gen") == 0) genererpasswd(p, 14);
            
            int min, maj, ch, sy;
            int len = analysepasswd(p, &min, &maj, &ch, &sy);
            printf("MDP: %s | Score: %d/100\n", p, scorepwd(len, min, maj, ch, sy));
            sodium_memzero(p, sizeof(p)); // Nettoyage
        }
    }

    // Nettoyage final du mot de passe maître de la RAM avant de quitter
    sodium_memzero(master_pwd, sizeof(master_pwd));
    return 0;
}