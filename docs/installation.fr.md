> La version de référence est la version anglaise ([installation.md](installation.md)) ; cette traduction la suit.

# Installation et vérification (Windows 10/11)

RV MailAuth s'exécute **localement** sur le PC Windows 10 ou 11 de l'expert (x64). Il ne demande ni droits
d'administrateur, ni runtime (runtime C statique), ni réseau, sauf pour l'horodatage RFC 3161 facultatif et la
recherche facultative des clés DKIM avec `--online`. Cette page couvre : obtenir une version, **prouver qu'il s'agit de
la compilation authentique**, l'installer (zip portable ou programme d'installation par utilisateur), l'autotest du
premier lancement, l'usage hors ligne, la compilation à partir des sources pour les auditeurs, l'emplacement des
fichiers et la désinstallation.

Pourquoi la vérification compte : un tribunal peut demander comment vous savez que le programme exécuté est celui
dont un expert a examiné le code source. Les étapes 2–4 et 6 apportent cette réponse ; conservez leur sortie au
dossier ([admissibility.md](admissibility.md#examiner-checklist-before-filing-a-report), étape 3, en anglais).

```mermaid
flowchart TB
    A["1 · Télécharger les fichiers de la version<br/>zip ou setup.exe + SHA256SUMS"] --> B["2 · SHA-256 de chaque fichier<br/>= SHA256SUMS ?"]
    B -->|non| X["Arrêt : ne pas utiliser<br/>retélécharger, signaler"]
    B -->|oui| C["3 · Provenance<br/>gh attestation verify"]
    C -->|échec| X
    C -->|ok| D["4 · Authenticode<br/>(quand la version est signée)"]
    D --> E{"5 · Installer"}
    E -->|portable| F["Débloquer + extraire le zip"]
    E -->|programme d'installation| G["setup.exe par utilisateur<br/>sans administrateur"]
    F --> H["6 · self-test + exécution d'exemple<br/>résumé attendu, verify-log"]
    G --> H
    H -->|ok| J["Prêt pour les affaires<br/>conservez les sorties"]
    H -->|différent| X
```

## Prérequis

| Élément | Exigence |
| --- | --- |
| Système d'exploitation | Windows 10 ou 11, x64 (`MinVersion=10.0`, `ArchitecturesAllowed=x64compatible` dans le programme d'installation). Linux/macOS : compiler à partir des sources. |
| Droits | Utilisateur standard. Le programme d'installation est par utilisateur (`PrivilegesRequired=lowest`). |
| Disque | Les deux exécutables et la documentation (quelques Mo) ; les sorties demandent environ 11 fichiers de rapport par élément pour une langue (19 avec `--lang all`) plus les journaux. |
| Mémoire | Les fichiers sont hachés par blocs de 1 Mio. Chaque message est analysé dans son propre processus d'analyse, limité par `--worker-memory-mb` (par défaut 1024 Mio) et `--max-message-mb` (par défaut 200 Mio) ; un mbox est découpé par une lecture séquentielle des octets, sa taille n'augmente donc pas la mémoire utilisée. |
| Graphisme | Aucun prérequis : la GUI fonctionne aussi sur des machines virtuelles sans pilote GPU (rendu logiciel). |
| Réseau | Aucun, sauf la demande d'horodatage facultative et les recherches de clés avec `--online` (voir l'[étape 7](#7-usage-hors-ligne-et-sur-poste-isolé)). |
| Vérification des versions | Facultative, simple avertissement : l'application de bureau au démarrage et `rv-mailauth update-check` lisent la page publique de la dernière version sur github.com ([Vérification des versions](#vérification-des-versions)) ; `RV_NO_UPDATE_CHECK=1` la désactive. |

## 1. Téléchargement

Fichiers de la version sur la page GitHub Releases du dépôt (`Panacota96/rv-mailauth`) :

| Fichier | Ce que c'est |
| --- | --- |
| `rv-mailauth-X.Y.Z-windows-x64.zip` | Portable : `rv-mailauth.exe`, `rv-mailauth-gui.exe`, README, LICENSE, COMMERCIAL.md, NOTICE, CHANGELOG, `docs/`, `examples/` |
| `rv-mailauth-X.Y.Z-windows-x64-setup.exe` | Programme d'installation Inno Setup, par utilisateur |
| `SHA256SUMS` | SHA-256 du zip, du programme d'installation et du SBOM (format `sha256sum` : `<empreinte>  ./<fichier>`) |
| `sbom.cdx.json` | Nomenclature logicielle CycloneDX (chaque dépendance Rust et sa version) |

Placez-les dans un même dossier, par ex. `C:\Rakvor\downloads\rv-mailauth-0.1.0\`.

## 2. Vérifier le téléchargement

```powershell
cd C:\Rakvor\downloads\rv-mailauth-0.1.0
Get-Content .\SHA256SUMS | ForEach-Object {
    $hash, $name = $_ -split '\s+', 2
    $name = $name.TrimStart('*').Replace('./', '')
    if (Test-Path $name) {
        $actual = (Get-FileHash -Algorithm SHA256 $name).Hash.ToLower()
        if ($actual -eq $hash) { "OK    $name" } else { "FAIL  $name  (got $actual)" }
    } else { "skip  $name (not downloaded)" }
}
```

```bash
sha256sum -c --ignore-missing SHA256SUMS      # Linux, ou Git Bash sous Windows
```

Chaque fichier téléchargé doit afficher `OK`. `SHA256SUMS` est produit par le même workflow et n'est pas lui-même
attesté : l'étape 3 est le contrôle le plus fort.

## 3. Vérifier la provenance de la compilation

Chaque zip et programme d'installation porte une attestation de provenance de compilation GitHub
(`actions/attest-build-provenance`) : une déclaration signée indiquant que ce fichier précis a été compilé par le
workflow de publication du dépôt à partir d'un commit donné. Sur un poste connecté à internet, avec la CLI GitHub :

```powershell
gh attestation verify .\rv-mailauth-0.1.0-windows-x64.zip --repo Panacota96/rv-mailauth
gh attestation verify .\rv-mailauth-0.1.0-windows-x64-setup.exe --repo Panacota96/rv-mailauth
```

La sortie nomme le workflow (`.github/workflows/release.yml`) et le commit source ; notez les deux. Pour un
laboratoire isolé, vérifiez sur un poste connecté et transportez les fichiers vérifiés sur un support protégé en
écriture (la CLI GitHub peut aussi télécharger le paquet d'attestation et la racine de confiance pour des contrôles
hors ligne ; voir `gh attestation verify --help`). `SHA256SUMS` et le SBOM ne sont pas attestés.

## 4. Vérifier la signature Authenticode (versions signées)

Le workflow de publication signe `rv-mailauth.exe`, `rv-mailauth-gui.exe` et le programme d'installation **uniquement
lorsqu'un certificat de signature de code est configuré** pour le dépôt. Les versions sont signées avec le certificat
de signature de code **interne** de Rakvor (« Rakvor Code Signing (internal) », émis par « Rakvor Internal Code Signing
Root CA »). Ce n'est pas un certificat public : Windows ne lui fait confiance que sur les postes où la racine Rakvor
est installée (les ordinateurs portables de Rakvor, puisque l'outil est utilisé localement et n'est pas distribué).
Les auditeurs et les clients vérifient les versions avec les étapes 2–3 et peuvent inspecter la signature avec
l'empreinte de la racine ci-dessous.

Installez la racine une fois par poste Rakvor (PowerShell, en tant qu'utilisateur qui exécute l'outil ; le fichier est
`packaging/signing/rakvor-code-signing-root.cer` dans le dépôt) :

```powershell
# Vérifiez d'abord l'empreinte ; elle doit être exactement :
#   SHA-256 DC9BA1A2FCD4F0633C5214B7CCEB25BED8F3F7D9EBAF111590250CBCAA83DF60
(New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 .\rakvor-code-signing-root.cer).GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA256)
Import-Certificate -FilePath .\rakvor-code-signing-root.cer -CertStoreLocation Cert:\CurrentUser\Root
```

Windows affiche une boîte de confirmation pour la nouvelle racine ; acceptez-la uniquement si l'empreinte correspond.
Sans la racine, `Get-AuthenticodeSignature` indique `UnknownError` (chaîne vers une racine non approuvée) et
SmartScreen peut quand même avertir au premier lancement. Vérifiez :

```powershell
Get-AuthenticodeSignature .\rv-mailauth-0.1.0-windows-x64-setup.exe |
    Format-List Status, StatusMessage, SignerCertificate, TimeStamperCertificate
# après extraction du zip :
Get-AuthenticodeSignature .\rv-mailauth.exe, .\rv-mailauth-gui.exe | Format-Table Status, Path
```

| Statut | Signification |
| --- | --- |
| `Valid` | Signé et intact ; le signataire doit être « Rakvor Code Signing (internal) » |
| `UnknownError` | Signé, mais la racine Rakvor n'est pas installée sur ce poste (installez-la comme ci-dessus) |
| `NotSigned` | La version a été compilée sans certificat de signature : appuyez-vous sur les étapes 2–3 ; Windows SmartScreen avertira |
| `HashMismatch` / autre | Arrêtez : le fichier a été modifié après sa signature |

Avec le Windows SDK, `signtool verify /pa /v rv-mailauth.exe` donne la chaîne complète.

## 5. Installer

### 5a. Zip portable

```powershell
# seulement après les étapes 2–4
Unblock-File .\rv-mailauth-0.1.0-windows-x64.zip
Expand-Archive .\rv-mailauth-0.1.0-windows-x64.zip -DestinationPath C:\Rakvor\tools\rv-mailauth-0.1.0
cd C:\Rakvor\tools\rv-mailauth-0.1.0
.\rv-mailauth.exe --version
```

Gardez un dossier par version, pour pouvoir relancer une ancienne affaire avec la version exacte consignée dans son
`environment.json`. Facultatif, pour la session en cours seulement : `$env:Path += ";C:\Rakvor\tools\rv-mailauth-0.1.0"`.

### 5b. Programme d'installation (par utilisateur, sans administrateur)

Double-cliquez sur `rv-mailauth-X.Y.Z-windows-x64-setup.exe` (assistant en anglais, espagnol ou français). Il installe
dans `%LOCALAPPDATA%\Programs\Rakvor\RV MailAuth\`, crée un groupe *Rakvor* dans le menu Démarrer (application +
documentation) et propose deux tâches : **Add the rv-mailauth command to PATH** (PATH de l'utilisateur, cochée à la
première installation) et une icône sur le bureau. Ouvrez ensuite un **nouveau** terminal pour que le PATH s'applique.

Sans intervention :

```powershell
.\rv-mailauth-0.1.0-windows-x64-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /TASKS="addtopath"
```

Le programme d'installation copie les exécutables, README, LICENSE, COMMERCIAL.md, NOTICE, CHANGELOG, `docs\`, les
éléments d'exemple (`examples\sample\evidence\`) et les clés publiques de l'échantillon
(`examples\sample\dkim-keys.txt`), pas les scripts de l'échantillon, ni `expected_findings.json`, ni
`expected_hashes.csv` (ils sont dans le zip et dans l'arborescence des sources).

### 5c. Bibliothèques natives

Aucune. RV MailAuth, ce sont deux exécutables autonomes : le hachage, l'analyse MIME (mail-parser), la vérification
DKIM/ARC (mail-auth avec son moteur `rust-crypto` en Rust pur, et non la bibliothèque C aws-lc), le lecteur de fichiers
composés d'Outlook, la Public Suffix List (un fichier de données compilé dans l'exécutable), l'écriture des PDF, le
client RFC 3161 et le signataire CMS sont compilés dans l'exécutable (crates en Rust pur, listées dans le SBOM), et le
runtime C est lié statiquement (`.cargo/config.toml`). Il n'y a aucune DLL à vérifier ni à garder à côté des
exécutables.

## 6. Self-test au premier lancement et exemple

```powershell
rv-mailauth --version
rv-mailauth self-test
```

`self-test` affiche `PASS` pour md5, sha1, sha256, sha512, sha3-256 et blake3 (réponses connues pour `"abc"`), code
de sortie 0. Il ne teste que les implémentations d'empreinte. Lancez ensuite l'échantillon synthétique (16 fichiers de
courriel, 19 éléments), qui exerce DKIM et ARC avec les clés publiques de l'échantillon, les contrôles de dates, de
sauts et de BEC, le traitement des `.msg` et des mbox, les rapports et la chaîne d'audit :

```powershell
# zip portable (script inclus) : self-test, keys show, analyse de l'échantillon, verify-log, constatations par
# élément comparées à expected_findings.json, hashes.csv comparé à expected_hashes.csv
.\examples\sample\run.ps1 -Bin .\rv-mailauth.exe

# programme d'installation (aucun script installé) : lancez-le à la main dans un dossier temporaire
$app = "$env:LOCALAPPDATA\Programs\Rakvor\RV MailAuth"
$out = Join-Path $env:TEMP "rv-mailauth-check"
rv-mailauth analyze -i "$app\examples\sample\evidence" --hash sha256,md5 --out $out --progress none --no-timestamp `
  --dkim-keys "$app\examples\sample\dkim-keys.txt" --own-domain acme.example
$LASTEXITCODE                                  # 3 : l'échantillon contient des messages altérés (expected_findings.json)
rv-mailauth verify-log (Get-ChildItem "$out\logs" | Select-Object -Last 1).FullName   # OK … chain intact
```

Résumé attendu : **19 éléments (16 fichiers + 3 messages du mbox), 0 erreur, constatations élevées 2, moyennes 13,
faibles 7, info 10**, code de sortie **3** : deux messages dont le corps ne correspond plus à leur signature DKIM
(`03-body-edited.eml` et le message 2 de `12-mailbox.mbox`) ; les codes exacts par élément sont dans
`examples\sample\expected_findings.json` et dans le tableau de [examples/README.md](../examples/README.md) (en
anglais). Sans `--dkim-keys` le résumé change (les signatures deviennent `DKIM_KEY_NOT_AVAILABLE`), donnez donc
toujours le fichier de clés de l'échantillon. La colonne SHA-256 de `hashes.csv` doit être égale à
`examples\sample\expected_hashes.csv` (calculé indépendamment avec Python), par exemple :

| Fichier | Taille | SHA-256 |
| --- | --: | --- |
| `01-clean-rsa.eml` | 1464 | `d774e6fb20d569075f2767ee4dd92136071f6c2fa81ce0979600069b89596f59` |
| `02-clean-ed25519.eml` | 1063 | `35736d319dd2c2b75b04a48253a5f39c4d3c2a3a65a7479b9f30bde0e1c42f1d` |

`run.ps1` / `run.sh` font eux-mêmes les deux comparaisons : ils comparent les codes de constatation et l'état de
chaque élément avec `expected_findings.json` (`findings and status match expected_findings.json (19 items)`), et la
taille, le SHA-256 et le MD5 de chaque fichier avec `expected_hashes.csv` (`hashes.csv matches expected_hashes.csv
(16 files: size, SHA-256, MD5)`), et sortent avec 3 à la moindre différence. Pour le programme d'installation (aucun
script n'est installé), comparez `$out\logs\<RUN-ID>\hashes.csv` avec le `expected_hashes.csv` de l'arborescence des
sources, ou lancez `python tests\verify_chain.py <dossier des journaux>` depuis l'arborescence des sources, qui hache
de nouveau chaque fichier de `hashes.csv` et chaque sortie consignée par le journal d'audit.

Conservez la sortie de la console et le dossier de l'exécution comme trace de cette vérification.

## 7. Usage hors ligne et sur poste isolé

En dehors de la vérification des versions facultative ([Vérification des versions](#vérification-des-versions)), le
réseau n'est utilisé qu'à deux endroits : la demande d'horodatage RFC 3161 (un HTTP POST d'une empreinte de 32 octets
vers la TSA, [src/core/src/trust.rs](../src/core/src/trust.rs)) et, seulement avec `analyze --online` (GUI :
*Interroger les clés DNS d'aujourd'hui*), les requêtes DNS TXT des clés DKIM manquantes
`selector._domainkey.domain` par le résolveur du système, dans le processus principal
([src/core/src/dnsfetch.rs](../src/core/src/dnsfetch.rs)) ; les processus d'analyse ne contiennent aucun code réseau.
`--online` est désactivé par défaut, et chaque requête révèle au DNS quels domaines sont examinés. Il n'y a ni
télémétrie ni contrôle de licence.

| Pour désactiver l'horodatage | Comment |
| --- | --- |
| Une exécution de la CLI | `--no-timestamp` |
| Toutes les exécutions de la CLI sur ce poste / cette session | `$env:RV_NO_TIMESTAMP = "1"` (ou définissez-la comme variable d'environnement de l'utilisateur) |
| GUI | décochez **4. Confiance → Horodatage qualifié** avant *Lancer l'analyse* |
| Recherches de clés DKIM | n'ont jamais lieu sans `--online` (GUI : *5. Options → Interroger les clés DNS d'aujourd'hui*) |

Une exécution hors ligne avec l'horodatage activé se termine quand même : elle consigne `timestamp_pending` et le
rapport statistique affiche un avertissement. Plus tard, sur un poste qui peut joindre la TSA, lancez
`rv-mailauth timestamp <dossier des journaux>` (la commande revérifie la chaîne, puis ajoute `timestamp_obtained`).
Pour utiliser une TSA interne ou qualifiée, indiquez `--tsa-url` (voir
[admissibility.md](admissibility.md#53-eidas--regulation-eu-9102014-as-amended-by-eu-20241183)). Malgré le libellé
de la GUI, l'horodatage n'est qualifié au sens d'eIDAS que si l'adresse est celle d'un prestataire de services de
confiance qualifié (QTSP) inscrit sur une liste de confiance de l'UE ; l'adresse par défaut (DigiCert) ne l'est pas.
La restriction
réseau n'est pas imposée par le système ; sur un poste connecté, une règle sortante du pare-feu Windows pour
`rv-mailauth.exe` / `rv-mailauth-gui.exe` n'autorisant que le serveur de la TSA l'impose.

## 8. Compiler à partir des sources pour les auditeurs

### Chaîne d'outils

| Élément | Version |
| --- | --- |
| Rust | Fixé par [rust-toolchain.toml](../rust-toolchain.toml) : **1.99.1** avec rustfmt et clippy ; `rustup` l'installe et le sélectionne automatiquement dans l'arborescence des sources. `Cargo.toml` déclare `rust-version = "1.98"` (édition 2024) comme minimum, imposé par mail-parser 1.0 ([development.md](development.md#toolchain-pin), en anglais). Pour correspondre exactement à une version, utilisez le compilateur consigné dans le `environment.json` de cette version → `tool.rustc` (p. ex. `rustc 1.99.1 (58cf8f9c3 2026-10-13)`). |
| Éditeur de liens Windows | Visual Studio 2022 Build Tools, charge de travail *Desktop development with C++* (MSVC + Windows SDK) ; cible `x86_64-pc-windows-msvc`. Le CRT statique est défini dans `.cargo/config.toml`. |
| Linux | Aucun paquet système n'est nécessaire pour compiler la CLI. |
| Facultatif | Python 3.12 avec `blake3 jsonschema pyhanko dkimpy pynacl` pour les vérificateurs indépendants, l'oracle DKIM et les tests de confiance (`RV_TEST_PYTHON=python`). |

### Compilation

```powershell
git clone https://github.com/Panacota96/rv-mailauth.git
cd rv-mailauth
git checkout v0.1.0                       # the tag of the release under review
rustc --version                           # must print the pinned 1.99.1
cargo build --release --locked -p rv-mailauth-cli -p rv-mailauth-gui
.\target\release\rv-mailauth.exe self-test
.\examples\sample\run.ps1 -Bin .\target\release\rv-mailauth.exe
cargo test --workspace --locked            # unit + integration tests (trust tests skip without pyhanko, the DKIM oracle without dkimpy)
```

```bash
# Linux
cargo build --release --locked -p rv-mailauth-cli
target/release/rv-mailauth self-test && examples/sample/run.sh target/release/rv-mailauth
python3 tests/verify_chain.py examples/sample/out/logs/$(ls examples/sample/out/logs | tail -n 1)
# entre profils : un dossier d'affaire écrit par le profil Python de la forge doit se vérifier avec cette version
python3 tests/golden/unpack.py tests/golden/case-by-python.zip.b64 /tmp/golden
target/release/rv-mailauth verify-case /tmp/golden/CASE-GOLDEN
```

`--locked` refuse de compiler si `Cargo.lock` devait changer : l'ensemble des dépendances est donc celui listé dans
`environment.json` → `dependencies` et dans `sbom.cdx.json`. La version du produit vient de `version.txt` ; les
versions des crates dans `Cargo.toml` restent fixes, si bien qu'une version publiée ne modifie jamais le fichier de
verrouillage.

### Reproduire les empreintes d'une version

Soyez précis sur ce qui peut ou non correspondre bit à bit dans cette version (lacune G22) :

| Artefact | Identique bit à bit à la version publiée ? | Comment le vérifier |
| --- | --- | --- |
| Fichiers de `docs/`, `examples/` | Oui (depuis git ; fins de ligne LF sauf `*.ps1`, `*.iss`) | `git ls-files` + `Get-FileHash` face au zip extrait |
| `rv-mailauth.exe`, `rv-mailauth-gui.exe` | **Non garanti** : les chemins ne sont pas réécrits et l'en-tête PE porte des données de l'édition de liens. Le compilateur est celui fixé dans `rust-toolchain.toml` (les deux workflows lancent `rustup toolchain install`, qui lit ce fichier ; confirmez avec `environment.json` → `tool.rustc` d'une exécution de la version) | L'attestation de provenance (étape 3) lie le binaire publié au workflow et au commit ; comparez ensuite le comportement (ci-dessous) |
| zip, programme d'installation | Non (horodatages de l'archive) | Attestation (étape 3) |

**Équivalence fonctionnelle** : lancez l'exemple avec le binaire publié et avec votre compilation, puis comparez les
empreintes et les constatations de chaque élément :

```bash
python - "<release-out>/reports/<RUN-ID>" "<your-out>/reports/<RUN-ID>" <<'EOF'
import glob, json, sys
def load(run):
    out = {}
    for p in sorted(glob.glob(f"{run}/items/*/technical.json")):
        t = json.load(open(p, encoding="utf-8"))
        out[t["item"]["file_name"]] = (t["hashes"], t["item"]["detected_type"],
                                       [(f["code"], f["severity"], f["params"]) for f in t["findings"]])
    return out
a, b = load(sys.argv[1]), load(sys.argv[2])
print("identical findings and digests" if a == b else "DIFFERENT: " + ", ".join(k for k in a if a.get(k) != b.get(k)))
EOF
```

Lancez l'échantillon avec `--dkim-keys examples/sample/dkim-keys.txt --own-domain acme.example` des deux côtés.

## 9. Emplacement des fichiers

| Quoi | Emplacement |
| --- | --- |
| Programme (installation) | `%LOCALAPPDATA%\Programs\Rakvor\RV MailAuth\` (`rv-mailauth.exe`, `rv-mailauth-gui.exe`, `docs\`, `examples\sample\evidence\`, `examples\sample\dkim-keys.txt`, `unins000.exe`) |
| Programme (portable) | le dossier que vous avez extrait |
| Entrée du PATH (tâche du programme d'installation) | variable d'environnement de l'utilisateur `Path` (`HKCU\Environment`) |
| Sorties des exécutions | `--out` (par défaut `.\rakvor-out` **relatif au dossier courant**) : `logs\<RUN-ID>\` (avec `review.jsonl` dès que des messages sont ouverts dans la visionneuse), `reports\<RUN-ID>\`. Avec `--case-dir` : `<CASE>\runs\rv-mailauth\<RUN-ID>\`. La GUI utilise son champ *Dossier de sortie* (ou le dossier de l'affaire) |
| Dossier de l'affaire | là où vous le créez avec `--case-dir` (`case.json`, `case-log.jsonl`, `evidence\`, `runs\`) |
| Réglages de la GUI | non conservés : chaque lancement repart des valeurs par défaut ; chaque modification faite avant une exécution est consignée dans le journal d'audit de cette exécution (`ui_*`) |
| Certificat de signature | là où vous le gardez ; seuls son chemin, son sujet et son empreinte SHA-256 sont journalisés, jamais le mot de passe |
| Fichiers de clés DKIM | là où vous les rangez ; `keys import` écrit le fichier de clés que vous nommez et son propre `logs\<RUN-ID>\` sous `--out` |
| Données locales, caches, fichiers temporaires | aucun (les processus d'analyse n'écrivent que dans les dossiers des éléments de l'exécution) |

## 10. Désinstaller

- **Programme d'installation :** *Paramètres → Applications → Applications installées → RV MailAuth → Désinstaller*,
  ou lancez `"%LOCALAPPDATA%\Programs\Rakvor\RV MailAuth\unins000.exe"`. Il supprime les fichiers installés et les
  raccourcis. **L'entrée du PATH de l'utilisateur n'est pas supprimée** dans cette version ; supprimez-la avec :

  ```powershell
  $dir = "$env:LOCALAPPDATA\Programs\Rakvor\RV MailAuth"
  $p = [Environment]::GetEnvironmentVariable("Path", "User").Split(";") | Where-Object { $_ -and $_ -ne $dir }
  [Environment]::SetEnvironmentVariable("Path", ($p -join ";"), "User")
  ```

- **Portable :** supprimez le dossier.
- **Conservés volontairement** (dans les deux cas) : les sorties des exécutions et les dossiers d'affaire (pièces de
  l'affaire). Gardez le zip de la version et `SHA256SUMS` de chaque version utilisée dans une affaire, pour pouvoir la
  relancer.

## 11. Dépannage de l'installation

| Symptôme | Cause et solution |
| --- | --- |
| SmartScreen « Windows a protégé votre ordinateur » (éditeur inconnu) | SmartScreen juge un fichier sur la **réputation** d'un certificat de confiance publique ; la racine interne Rakvor n'en est pas un, donc l'avertissement apparaît même lorsque la signature est `Valid` (et toujours quand elle est `NotSigned`). Uniquement après réussite des étapes 2–4 : *Informations complémentaires → Exécuter quand même*, ou retirez d'abord la marque de fichier téléchargé avec `Unblock-File .\<fichier>` (sur le zip, **avant** de l'extraire). L'avertissement ne disparaît définitivement qu'avec un certificat public (voir `docs/release-process.md` §5). |
| `rv-mailauth` n'est pas reconnu | La tâche PATH n'a pas été choisie, ou le terminal a été ouvert avant l'installation : ouvrez un nouveau terminal ou utilisez le chemin complet. |
| `self-test` affiche `FAIL` | N'utilisez pas cette compilation pour des éléments de preuve ; retéléchargez et refaites les étapes 2–4. |
| Le résumé de l'exemple diffère de l'étape 6 | Mauvaise version ou fichiers d'exemple modifiés ; comparez `environment.json` aux notes de version et les empreintes de l'exemple à `expected_hashes.csv`. |
| Fenêtre de la GUI vide ou très lente sur une machine virtuelle | Sans pilote GPU, le rendu logiciel est utilisé ; donnez plus de CPU à la machine virtuelle. |
| La compilation à partir des sources télécharge un autre compilateur | Attendu : rustup installe la 1.99.1 fixée dans `rust-toolchain.toml`. Hors ligne, installez-la avant (`rustup toolchain install 1.99.1 --profile minimal`). |

## Vérification des versions

Une version plus récente est-elle publiée ? L'outil peut vous le dire ; il ne se met jamais à jour tout seul.

| | |
| --- | --- |
| Quand | L'application de bureau vérifie une fois au démarrage, en arrière-plan (un bandeau avec la page de la version n'apparaît que lorsqu'une version plus récente existe). La CLI ne vérifie qu'avec `rv-mailauth update-check` (`--json` pour les scripts ; sortie 0 = dernière, 3 = version plus récente, 1 = vérification impossible). Aucune autre commande ne contacte le réseau pour cela. RV Hub vérifie chaque outil qu'il liste. |
| Ce qui est envoyé | Un HTTPS GET de `https://github.com/Panacota96/rv-mailauth/releases/latest` (la redirection est lue, pas suivie) avec `User-Agent: rv-mailauth/<version>` et aucun autre en-tête, cookie ni paramètre : rien sur l'affaire, les éléments, l'expert ou le poste. |
| Ce que cela fait | Cela nomme la version plus récente et sa page. Rien n'est jamais téléchargé ni installé : téléchargez la version et vérifiez-la (`SHA256SUMS`, chaîne Authenticode jusqu'à la racine Rakvor) comme dans [Vérifier le téléchargement](#2-vérifier-le-téléchargement) avant usage. |
| Audit | La vérification ne fait pas partie d'une exécution et n'est inscrite dans aucun journal d'audit ; une vérification en échec ou lente (hors ligne, délai de 5 s) ne bloque jamais l'outil. |
| La désactiver | `RV_NO_UPDATE_CHECK=1` (toute valeur sauf vide ou `0`), ou le fichier `update-check-off` dans `%APPDATA%\Rakvor` (écrit par le réglage de RV Hub) : désactivée pour chaque outil Rakvor de ce poste. |
| Code | [src/core/src/update.rs](../src/core/src/update.rs) (partagé, identique octet pour octet, par chaque outil Rakvor) |
