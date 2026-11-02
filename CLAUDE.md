# CLAUDE.md — Decryptor (EloaneDecryptor)

Petit utilitaire **Qt 6 Widgets + OpenSSL** (C++17, `main.cpp` unique ~420 lignes, projet CMake `EloaneDecryptor`) : on ouvre ou glisse un fichier `.eloane` exporté par l'IHM, on saisit le mot de passe, il affiche le **JSON** déchiffré. Commits en français.

## Format et crypto (miroir de `cryptoutils.*` de l'IHM)

AES-256 + HMAC-SHA256, dérivation **PBKDF2-HMAC-SHA256 600 000 itérations**, magic `ELO\x01` (v1) / `ELO\x02` (v2), blob maître de 80 octets (clés AES + HMAC + padding). Le code de déchiffrement est une **copie autonome** de celui de l'IHM (`namespace EloaneDecrypt`) : toute évolution du format de l'IHM (magic, itérations, structure) doit être reportée ici, sinon les exports ne s'ouvrent plus.

## Règles

- `main.cpp` contient une clé maître en dur (`MASTER_KEY`). Ne pas l'afficher, la copier ailleurs ni l'étendre ; signaler tout nouveau secret en dur. `..\clé_uni_decrypt.txt` est un secret : ne pas le lire, l'afficher ni le commiter.
- Ne pas affaiblir la vérification HMAC (vérifier avant déchiffrement) ni baisser le nombre d'itérations PBKDF2. Effacer les clés et mots de passe de la mémoire (`OPENSSL_cleanse`) quand c'est déjà fait ailleurs ; ne pas le retirer.
- Ne jamais écrire le JSON déchiffré sur disque sans demande explicite.

## Build

Windows : kit Qt 6.8.3 MSVC 2022, OpenSSL dans `C:/Program Files/OpenSSL-Win64` (`OPENSSL_ROOT_DIR`), `cmake -B build -S . && cmake --build build`. Raspberry Pi : scripts `tools/build_decryptor_*`, `deploy_decryptor_*`, `run_decryptor_*` (`.sh` en LF, `.cmd` appellent WSL). `build/` est généré : ne pas l'éditer. Le dépôt contient des fichiers de build/IDE modifiés (`.qtcreator/*.user`, `build/**/LastTest.log`) : ne pas les commiter.
