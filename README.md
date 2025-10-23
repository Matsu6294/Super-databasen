# 🔐 AI DATABASEN

En krypterad databas med grafiskt gränssnitt för säker lagring och hantering av filer, text och bilder. Byggd med Rust, eframe/egui och militär-grad kryptering.

**Version:** 0.1.0  
**Skapad:** 22 oktober 2025  
**Språk:** Rust 2021 Edition

---

## 📋 Innehållsförteckning

- [Funktioner](#-funktioner)
- [Säkerhet](#-säkerhet)
- [Segmentstruktur](#-segmentstruktur)
- [Installation](#-installation)
- [Användning](#-användning)
- [Teknisk Specifikation](#-teknisk-specifikation)
- [Beroenden](#-beroenden)

---

## ✨ Funktioner

AI Databasen har 7 huvudfunktioner som täcker alla behov för säker filhantering:

### 1. 📄 Ladda upp fil

Krypterar och sparar enskilda filer till databasen.

**Funktionalitet:**
- Stöd för alla filtyper (text, bilder, dokument)
- Automatisk filtypsdetektering
- ID-baserad organisering med lösenordsskydd
- Bildoptimering för minskad lagringsstorlek

**Användning:**
1. Ange unikt ID för filen
2. Skapa säkert lösenord
3. Välj fil från filväljaren
4. Klicka "Kryptera & Spara"

### 2. 📁 Ladda upp mapp (Bulkimport)

Importerar flera filer samtidigt från en mapp.

**Funktionalitet:**
- Batch-uppladdning av flera filer
- Automatisk numrering (ID_1, ID_2, ID_3...)
- Progress bar med live-uppdateringar
- Multi-threaded bearbetning för snabbhet
- Stöd för stora bildkataloger

**Användning:**
1. Ange bas-ID för alla filer
2. Skapa lösenord
3. Välj mapp med filer
4. Systemet numrerar automatiskt alla filer

### 3. 🔍 Se fil

Dekrypterar och visar innehållet från en krypterad post.

**Funktionalitet:**
- **Textvisning:** Formaterad textvisning med stöd för långa dokument
- **Tabellvisning:** Automatisk tabelldetektering och rendering
- **Bildvisning:** Högkvalitativ bildrendering upp till 400x400px
- **Redigerbar bildtext:** Lägg till och redigera beskrivningar
- **Sorterbar data:** Klicka på kolumnrubriker för att sortera tabeller

**Stödda format:**
- TEXT: Vanlig text och dokument
- IMAGE: JPEG, PNG, och andra bildformat
- Tabell-data med automatisk parsing

### 4. 🖼️ Se galleri

Visar alla bilder med samma ID i ett responsivt galleri.

**Funktionalitet:**
- 5-kolumners galleri-layout
- Automatisk thumbnail-generering
- Texture-caching för snabb rendering
- LRU-cache för minnesoptimering (max 50 texturer)
- Visar alla bilder för ett ID samtidigt
- Scrollbar för stora gallerier

**Användning:**
1. Ange ID som har flera bilder
2. Ange lösenord
3. Alla bilder dekrypteras och visas i galleriformat

### 5. 🗑️ Radera ID-kod

Raderar permanent alla poster associerade med ett specifikt ID.

**Funktionalitet:**
- Lösenordsverifiering innan radering
- Raderar ALLA filer med angivet ID
- Omskriver databasen utan raderade poster
- Säker återvinning av diskutrymme
- Varningsmeddelande före radering

**Säkerhet:**
- Kräver korrekt lösenord för verifiering
- Permanent radering - går ej att ångra
- Effektiv databasrensning

### 6. 🤖 Kontrollera AI (EXIF-detektering)

Identifierar AI-genererade bilder och videor genom EXIF-dataanalys.

**Funktionalitet:**
- Skannar mappar rekursivt efter bilder och videor
- EXIF-metadata-analys
- Detekterar AI-genererat innehåll från:
  - Midjourney
  - DALL-E
  - Stable Diffusion
  - Adobe Firefly
  - GPT-4 Vision
  - Runway ML
  - Synthesia
  - D-ID
  - Other AI tools

**Detekteringsmetoder:**
- Software-fält i EXIF
- Make/Model metadata
- UserComment-analys
- ImageDescription-nyckelord

**Output:**
- Lista över alla AI-genererade filer
- Filtyp (image/video)
- Orsak till detektering
- Fullständig filsökväg

### 7. 🎨 Designa databasen

Anpassar visuellt utseende och tema för applikationen.

**Funktionalitet:**
- **Färgkontroll:**
  - Primärfärg (knappar, accenter)
  - Bakgrundsfärg (huvudbakgrund)
  - Panelfärg (ramar och boxar)
  - Textfärg (huvudtext)
  - Felfärg (felmeddelanden)
  - Framgångsfärg (bekräftelser)

- **Layout-inställningar:**
  - Rundning (0-20px)
  - Mellanrum (5-30px)
  - Ramtjocklek (0-5px)
  - Fontstorlek (10-24pt)

- **Tema-hantering:**
  - Spara custom themes till YAML
  - Återställ till standardtema
  - Live preview av ändringar
  - Persistent tema mellan sessioner

**Filer:**
- `desig.yaml` - Sparade temainställningar
- `desig.rs` - Tema-engine

---

## 🔒 Säkerhet

AI Databasen använder militär-grad kryptering och säkerhetsprotokoll:

### Krypteringsalgoritmer

#### AES-256-GCM (Authenticated Encryption)
- **Cipher:** AES-256 (Advanced Encryption Standard)
- **Mode:** GCM (Galois/Counter Mode)
- **Nyckelstorlek:** 256 bitar
- **Fördelar:**
  - Autentiserad kryptering (AEAD)
  - Skyddar mot tampering
  - Verifierar dataintegritet
  - Industristandard för toppsäkerhet

#### Argon2id (Key Derivation)
- **Algoritm:** Argon2id (vinnare av Password Hashing Competition)
- **Version:** v0x13
- **Parameters:**
  - Memory: 131,072 KiB (128 MB) - fallback till lägre vid behov
  - Iterations: 4
  - Parallelism: 1
  - Output: 32-byte nyckel

**Fördelar:**
- Resistent mot GPU-attack
- Resistent mot sidokanalsattacker
- Kombinerar Argon2i och Argon2d för maximal säkerhet
- Rekommenderad av OWASP

### Nonce och Salt

- **12-byte random nonce** för varje krypteringsoperation
- **Kryptografiskt säker RNG** (rand::thread_rng)
- **Unik salt per lösenord** från master key
- **Deterministisk salt-generering** för samma lösenord

### Minnesäkerhet

```rust
// Säker minneshantering (valfri)
secure_mlock()   // Låser känslig data i RAM
secure_munlock() // Låser upp efter användning
zeroize()        // Nollställer känsliga variabler
```

**Funktioner:**
- Förhindrar känslig data från att swappas till disk
- Automatisk zeroize av lösenord efter användning
- Säker rensning av kryptonycklar

### Databasformat

Varje post i `personer.bin` innehåller:

```
[ID]:[NONCE_BASE64]:[ENCRYPTED_DATA_BASE64]
```

**Komponenter:**
- **ID:** Identifierare (klartext för indexering)
- **NONCE:** 12-byte random värde (Base64)
- **DATA:** AES-256-GCM krypterad payload (Base64)

**Säkerhetsegenskaper:**
- Ingen plaintext-data lagras
- Varje rad är oberoende krypterad
- Unika nonces förhindrar mönsterigenkänning
- GCM-tag verifierar integritet

### Lösenordshantering

**Aldrig lagrat i klartext:**
- Lösenord deriveras till nycklar med Argon2id
- Nycklar används för kryptering/dekryptering
- Nycklar zeroize:as omedelbart efter användning
- Ingen lösenordsdatabas - lösenord existerar bara i minnet

**Password Strength:**
- Starkt lösenord rekommenderas (12+ tecken)
- Stöd för specialtecken, siffror, stora/små bokstäver
- Ingen längdbegränsning

### Filoptimering

**Bildkomprimering:**
```rust
optimize_image_data() // Komprimerar bilder till 85% kvalitet
```

**Fördelar:**
- Minskar lagringsutrymme
- Snabbare kryptering/dekryptering
- Bibehåller visuell kvalitet
- Automatisk JPEG-optimering

### Säkerhetsrekommendationer

1. **Använd starka lösenord** - Minst 12 tecken med blandade teckentyper
2. **Unika ID:n** - Använd inte förutsägbara ID-mönster
3. **Backup regelbundet** - Kopiera `personer.bin` till säker plats
4. **Fysisk säkerhet** - Håll databas på krypterad disk
5. **Lösenordshanterare** - Använd för att komma ihåg komplexa lösenord

---

## 📦 Segmentstruktur

Koden i `AI_secure.rs` är organiserad i 9 tydliga segment för maximal underhållbarhet:

### Backend-Segment (Funktionsimplementationer)

#### SEGMENT 1: Grundläggande Funktioner (rad 37-220)
**Innehåll:**
- `secure_mlock()` / `secure_munlock()` - Minnesäkerhet
- `get_personer_path()` - Dynamisk databassökväg
- `derive_key()` - Argon2id key derivation
- `encrypt_data()` - AES-256-GCM kryptering
- `decrypt_data()` - AES-256-GCM dekryptering
- `generate_unique_id()` - ID-generering för bulkimport
- `list_all_ids()` - Lista alla ID:n i databasen
- `parse_table_data()` - Tabellparsing
- `update_encrypted_file()` - Uppdatera krypterade poster
- `optimize_image_data()` - Bildkomprimering

**Ansvar:** Grundläggande säkerhets- och krypteringsfunktioner

#### SEGMENT 2: Funktion 1 - Ladda upp fil (rad 221-318)
**Innehåll:**
- `encrypt_and_save_file()` - Huvudfunktion för fil-uppladdning

**Flöde:**
1. Validera filsökväg
2. Läs fil från disk
3. Detektera filtyp (text/bild)
4. Optimera om bild
5. Kryptera data
6. Spara till databas

#### SEGMENT 3: Funktion 2 - Ladda upp mapp (rad 319-369)
**Innehåll:**
- `ImportMsg` enum - Progress-meddelanden
- `bulk_import_folder()` - Multi-threaded import

**Flöde:**
1. Hitta alla filer i mapp
2. Generera unika ID:n
3. Bearbeta parallellt med progress-uppdateringar
4. Returnera statistik

#### SEGMENT 4: Funktion 3 - Se fil (rad 370-567)
**Innehåll:**
- `decrypt_file()` - Dekryptering av enskild post

**Flöde:**
1. Sök efter ID i databas
2. Derivera nyckel från lösenord
3. Dekryptera data
4. Returnera innehåll

#### SEGMENT 5: Funktion 4 - Se galleri (rad 568-670)
**Innehåll:**
- `decrypt_all_with_id()` - Dekryptera alla poster med samma ID

**Flöde:**
1. Sök efter ALLA poster med ID
2. Dekryptera varje post
3. Returnera lista med innehåll

#### SEGMENT 6: Funktion 5 - Radera ID-kod (rad 671-708)
**Innehåll:**
- `delete_id()` - Radera alla poster med ID

**Flöde:**
1. Läs hela databasen
2. Filtrera bort poster med ID
3. Skriv om databas

#### SEGMENT 7: Funktion 6 - Kontrollera AI (rad 709-714)
**Innehåll:**
- Dokumentation - Använder `detector.rs`

**Extern modul:**
- `detector::scan_directory()` - EXIF-analys
- `detector::AIDetectionResult` - Resultatstruktur

#### SEGMENT 8: Funktion 7 - Designa databasen (rad 715-720)
**Innehåll:**
- Dokumentation - Använder `desig.rs`

**Extern modul:**
- `desig::ThemeConfig` - Tema-struktur
- `desig::apply_theme()` - Tillämpa tema
- `desig::load_theme_from_yaml()` - Ladda från fil

#### SEGMENT 9: GUI - Huvudstruktur (rad 721-825)
**Innehåll:**
- `AppMode` enum - Navigationsstatus
- `MyApp` struct - Applikationsstatus
- `GalleryEntry` struct - Galleri-data
- `eframe::App` implementation

**AppMode states:**
```rust
Welcome      // Välkomstskärm
UploadFile   // Funktion 1
UploadFolder // Funktion 2
ViewFile     // Funktion 3
ViewGallery  // Funktion 4
DeleteId     // Funktion 5
CheckAI      // Funktion 6
Design       // Funktion 7
```

### GUI-Segment (Visningsfunktioner)

#### Välkomstskärm (rad 826-970)
**Innehåll:**
- `show_welcome()` - Huvudmeny med 7 knappar
- Lista över alla ID:n i databasen
- Navigation till alla funktioner

#### GUI Funktion 1: Ladda upp fil (rad 972-1044)
**Innehåll:**
- `show_upload_file()` - Formulär för fil-uppladdning
- Textfält för ID, lösenord, filväg
- Filväljare-dialog
- Kryptera & Spara-knapp

#### GUI Funktion 2: Ladda upp mapp (rad 1046-1149)
**Innehåll:**
- `show_upload_folder()` - Formulär för mapp-import
- Progress bar för batch-uppladdning
- Real-time status-uppdateringar
- Mappväljare-dialog

#### GUI Funktion 3: Se fil (rad 1150-1553)
**Innehåll:**
- `show_view_file()` - Visning av dekrypterat innehåll
- Stöd för text, tabell och bilder
- Redigerbar bildtext
- Redigerbara tabeller med sortering
- Spara-funktionalitet

#### GUI Funktion 4: Se galleri (rad 1554-1727)
**Innehåll:**
- `show_view_gallery()` - 5-kolumners galleri
- Texture caching och LRU-management
- Thumbnail-rendering
- Scrollbar för stora gallerier

#### GUI Funktion 5: Radera ID-kod (rad 1728-1803)
**Innehåll:**
- `show_delete_id()` - Raderingsformulär
- Varningsmeddelande
- Lösenordsverifiering
- Permanent radering

#### GUI Funktion 6: Kontrollera AI (rad 1804-1907)
**Innehåll:**
- `show_check_ai()` - AI-detektionsformulär
- Mappväljare
- Resultatvisning med scroll
- Detaljerad information per fil

#### GUI Funktion 7: Designa databasen (rad 1908-2159)
**Innehåll:**
- `show_design()` - Tema-editor
- Färgväljare för alla färger
- Sliders för layout-värden
- Spara/återställ-funktioner
- Live preview

### Main-Funktion (rad 2162-2184)

**Innehåll:**
- `main()` - Application entry point
- eframe initialisering
- Font setup
- Window konfiguration (1200x800)

---

## 🚀 Installation

### Förutsättningar

- **Rust:** 1.70+ (2021 edition)
- **OS:** Linux, macOS, Windows
- **RAM:** Minst 256 MB tillgängligt minne för Argon2

### Bygg från källkod

```bash
# Klona repository
git clone <repository-url>
cd Server

# Bygg release-version
cargo build --release

# Körbara filer skapas i:
# target/release/AI_secure
# target/release/AI_super3
# target/release/AI_super4
```

### Kör applikationen

```bash
# Kör release-version (rekommenderat)
./target/release/AI_secure

# Eller kör direkt med cargo
cargo run --release --bin AI_secure
```

---

## 📖 Användning

### Första gången

1. **Starta applikationen** - Välkomstskärmen visas
2. **Välj "Ladda upp fil"** - Kryptera din första fil
3. **Ange ID** - T.ex. "MinaFoton" eller "Dokument2025"
4. **Skapa lösenord** - Starkt och unikt
5. **Välj fil** - Använd filväljaren
6. **Spara** - Filen krypteras till databasen

### Visa krypterad data

1. **Välj "Se fil"** eller **"Se galleri"**
2. **Ange ID** - Samma som vid uppladdning
3. **Ange lösenord** - Korrekt lösenord krävs
4. **Visa** - Innehållet dekrypteras och visas

### Bulkimport

1. **Välj "Ladda upp mapp"**
2. **Ange bas-ID** - T.ex. "Semester"
3. **Välj mapp** - Med alla filer
4. **Importera** - Systemet numrerar automatiskt (Semester_1, Semester_2...)

### Tema-anpassning

1. **Välj "Designa databasen"**
2. **Justera färger** - Klicka på färgrutor
3. **Justera layout** - Använd sliders
4. **Spara** - Tema sparas till desig.yaml
5. **Starta om** - För att se alla ändringar

---

## 🔧 Teknisk Specifikation

### Filstruktur

```
Server/
├── AI_secure.rs           # Huvudapplikation (2184 rader)
├── desig.rs               # Tema-engine
├── detector.rs            # AI-detektering (EXIF)
├── Cargo.toml             # Projektberoenden
├── README.md              # Denna fil
├── SEGMENT.txt            # Segmentdokumentation
├── SEGMENT_VERIFIERING.md # Verifieringsrapport
├── personer.bin           # Krypterad databas (skapas automatiskt)
└── desig.yaml             # Tema-konfiguration (skapas vid anpassning)
```

### Databas

**Fil:** `personer.bin`  
**Format:** Newline-separated encrypted entries  
**Encoding:** Base64 för nonce och data  
**Plats:** Automatiskt detekterad:
1. Samma mapp som .exe
2. target/release/
3. /home/matsu/databasen/

### Minnesanvändning

- **Bas-applikation:** ~50 MB
- **Per textur (cached):** ~1-5 MB
- **Max texturer:** 50 (LRU cache)
- **Argon2 derivation:** 128 MB (fallback till 16 MB)

### Performance

- **Kryptering:** ~1-2 ms per fil
- **Dekryptering:** ~1-2 ms per fil
- **Bildoptimering:** ~50-100 ms per bild
- **Bulkimport:** Multi-threaded, ~100-200 filer/sekund

---

## 📚 Beroenden

Alla beroenden definierade i `Cargo.toml`:

```toml
[dependencies]
eframe = "0.28.0"           # GUI framework
egui = "0.28.0"             # Immediate mode GUI
image = "0.25"              # Bildbehandling
base64 = "0.22"             # Base64 encoding/decoding
aes-gcm = "0.10.3"          # AES-256-GCM kryptering
argon2 = "0.5.3"            # Key derivation
kamadak-exif = "0.5"        # EXIF-metadata läsning
zeroize = "1.7"             # Säker minnesrensning
rand = "0.8"                # Kryptografisk RNG
serde = "1.0"               # Serialisering
serde_yaml = "0.9"          # YAML-parsing
rfd = "0.12"                # Native file dialogs
egui_extras = "0.28"        # Extra egui-widgets
```

---

## 🛡️ Säkerhetsgarantier

### Vad applikationen GARANTERAR:

✅ AES-256-GCM kryptering för all lagrad data  
✅ Argon2id key derivation enligt best practices  
✅ Unika nonces för varje krypteringsoperation  
✅ Autentiserad kryptering med integritetskontroll  
✅ Ingen plaintext lagring av känslig data  
✅ Automatisk zeroize av känsliga variabler  

### Vad applikationen INTE garanterar:

⚠️ **Skydd mot keyloggers** - Använd betrodd miljö  
⚠️ **Skydd mot komprometterad OS** - Håll system uppdaterat  
⚠️ **Backup/redundans** - Användaren ansvarar för backups  
⚠️ **Lösenordsåterställning** - Glömt lösenord = förlorad data  
⚠️ **Skydd mot fysisk åtkomst** - Kryptera disk separat  

---

## 📄 Licens

Copyright © 2025. Alla rättigheter förbehållna.

---

## 🤝 Kontakt

För frågor, buggrapporter eller funktionsförslag, kontakta projektägaren.

---

## 📝 Changelog

### Version 0.1.0 (2025-10-22)
- ✨ Initial release
- ✨ 7 huvudfunktioner implementerade
- ✨ AES-256-GCM kryptering
- ✨ Argon2id key derivation
- ✨ GUI med eframe/egui
- ✨ AI-detektering via EXIF
- ✨ Anpassningsbara teman
- ✨ Bulkimport med progress tracking
- ✨ Galleri-visning med texture caching

---

**Byggd med ❤️ och Rust 🦀**

