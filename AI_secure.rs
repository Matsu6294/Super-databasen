// ═══════════════════════════════════════════════════════════════════════════════
// AI_DATABASEN - Krypterad databas med 7 huvudfunktioner
// ═══════════════════════════════════════════════════════════════════════════════
// Skapad: 22 oktober 2025
// 
// FUNKTIONER:
// 1. Ladda upp fil
// 2. Ladda upp mapp (bulkimport)
// 3. Se fil
// 4. Se galleri
// 5. Radera ID-kod
// 6. Kontrollera AI (EXIF-data)
// 7. Designa databasen
//
// ═══════════════════════════════════════════════════════════════════════════════

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine as _};
use eframe::egui;
use eframe::egui::{RichText, ScrollArea};
use image::GenericImageView;
use rand::RngCore;
use std::fs;
use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

mod desig;
use desig::{apply_theme, load_theme_from_yaml, setup_fonts};

mod detector;

// ═══════════════════════════════════════════════════════════════════════════════
// SEGMENT 1: GRUNDLÄGGANDE FUNKTIONER (Säkerhet, Kryptering, Nyckelhantering)
// ═══════════════════════════════════════════════════════════════════════════════

const PERSONER: &str = "/home/matsu/databasen/personer";
const PERSONER2: &str = "/home/matsu/databasen/personer.bin";
const MASTER_KEY: &str = "master_key_2025";

// Secure memory locking helper (simplified without libc)
fn secure_mlock(_data: &[u8]) -> Result<(), String> {
    // Memory locking disabled for compatibility
    Ok(())
}

fn secure_munlock(_data: &[u8]) -> Result<(), String> {
    // Memory unlocking disabled for compatibility
    Ok(())
}

// Hitta personer.bin dynamiskt
fn get_personer_path() -> String {
    // Försök hitta var programmet körs från
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let path = exe_dir.join("personer.bin");
            return path.to_string_lossy().to_string();
        }
    }
    
    // Fallback - försök olika platser
    let paths = vec![
        "target/release/personer.bin",
        "personer.bin",
        "/home/matsu/databasen/personer.bin",
        "/home/matsu/databasen/Server/target/release/personer.bin",
    ];
    
    for path in paths {
        if Path::new(path).exists() {
            return path.to_string();
        }
    }
    
    // Om ingen finns, skapa i target/release
    "target/release/personer.bin".to_string()
}

// Derive a 32-byte key using Argon2id
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mem_kib_choices = [131_072u32, 65_536u32, 32_768u32, 16_384u32];
    
    for &mem in &mem_kib_choices {
        if let Ok(params) = Params::new(mem, 4, 1, None) {
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut key = [0u8; 32];
            if argon2
                .hash_password_into(password.as_bytes(), salt, &mut key)
                .is_ok()
            {
                let _ = secure_mlock(&key);
                return key;
            }
        }
    }
    
    // Fallback
    let mut key = [0u8; 32];
    let pwd_bytes = password.as_bytes();
    if !pwd_bytes.is_empty() {
        for i in 0..32 {
            let p = pwd_bytes[i % pwd_bytes.len()];
            let s = salt[i % salt.len()];
            key[i] = p.wrapping_add(s).rotate_left((i % 8) as u32);
        }
    } else {
        for i in 0..32 {
            key[i] = salt[i % salt.len()].wrapping_mul(31).wrapping_add(i as u8);
        }
    }
    let _ = secure_mlock(&key);
    key
}

// Detektera och parsea tabelldata (rader med kolumner separerade med 2+ mellanslag)
fn parse_table_data(text: &str) -> Option<Vec<Vec<String>>> {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() < 2 {
        return None;
    }

    let mut all_rows = Vec::new();

    for line in &lines {
        let mut result = String::new();
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            if i + 1 < chars.len() && chars[i] == ' ' && chars[i + 1] == ' ' {
                result.push('|');
                while i < chars.len() && chars[i] == ' ' {
                    i += 1;
                }
            } else {
                result.push(chars[i]);
                i += 1;
            }
        }

        let columns: Vec<String> = result.split('|').map(|s| s.trim().to_string()).collect();

        if columns.len() >= 2 {
            all_rows.push(columns);
        } else {
            return None;
        }
    }

    if all_rows.is_empty() {
        return None;
    }
    let col_count = all_rows[0].len();
    if all_rows.iter().all(|row| row.len() == col_count) {
        Some(all_rows)
    } else {
        None
    }
}

// Optimera bilddata med EXIF-rotation
fn optimize_image_data(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut img = image::load_from_memory(data).map_err(|_| "Kunde inte läsa bild")?;
    
    // Läs EXIF-data och rotera bilden baserat på orientation
    if let Ok(exif_reader) = exif::Reader::new().read_from_container(&mut std::io::Cursor::new(data)) {
        if let Some(orientation) = exif_reader.get_field(exif::Tag::Orientation, exif::In::PRIMARY) {
            if let Some(orientation_val) = orientation.value.get_uint(0) {
                img = match orientation_val {
                    3 => img.rotate180(),
                    6 => img.rotate90(),
                    8 => img.rotate270(),
                    _ => img, // 1 = normal, ingen rotation
                };
            }
        }
    }
    
    let (width, height) = img.dimensions();
    let max_dimension = 800;
    let img = if width > max_dimension || height > max_dimension {
        let scale = max_dimension as f32 / width.max(height) as f32;
        let new_w = (width as f32 * scale) as u32;
        let new_h = (height as f32 * scale) as u32;
        img.resize(new_w, new_h, image::imageops::FilterType::Triangle)
    } else {
        img
    };
    
    // Komprimera tills bilden är under 1 MB
    let mut quality = 85;
    let max_size = 1_000_000; // 1 MB
    let rgb = img.to_rgb8();
    
    loop {
        let mut buffer = Vec::new();
        let mut cursor = std::io::Cursor::new(&mut buffer);
        let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut cursor, quality);
        encoder.encode(rgb.as_raw(), rgb.width(), rgb.height(), image::ExtendedColorType::Rgb8)
            .map_err(|_| "Encode fel")?;
        
        if buffer.len() <= max_size || quality <= 20 {
            return Ok(buffer);
        }
        
        quality -= 5;
    }
}

// Optimera bild för lagring (använder optimize_image_data)
fn optimize_image_for_storage(file_path: &str) -> Result<Vec<u8>, String> {
    let data = fs::read(file_path).map_err(|_| "Läsfel")?;
    optimize_image_data(&data)
}

// ═══════════════════════════════════════════════════════════════════════════════
// SEGMENT 2: FUNKTION 1 - LADDA UPP FIL
// ═══════════════════════════════════════════════════════════════════════════════

fn encrypt_and_save_file(identifier: &str, password: &str, file_path: &str) -> Result<(), String> {
    if !Path::new(file_path).exists() {
        return Err("Fil saknas".to_string());
    }
    
    let binary_data = fs::read(file_path).map_err(|_| "Läsfel")?;
    
    let is_image = if let Some(ext) = Path::new(file_path).extension() {
        let ext_lower = ext.to_string_lossy().to_lowercase();
        ext_lower == "jpg" || ext_lower == "jpeg" || ext_lower == "png" || ext_lower == "gif" || ext_lower == "webp"
    } else {
        false
    };
    
    let plaintext = if is_image {
        let filename = Path::new(file_path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        
        // Optimera bilden med EXIF-rotation
        let optimized_data = optimize_image_data(&binary_data).unwrap_or(binary_data.clone());
        
        // FÖRST base64, sedan krypteras detta
        let encoded = general_purpose::STANDARD.encode(&optimized_data);
        format!("IMAGE:{}|{}|", filename, encoded) // Tom beskrivning som kan redigeras senare
    } else {
        match String::from_utf8(binary_data.clone()) {
            Ok(text) => format!("TEXT:{}", text),
            Err(_) => format!("BINARY:{}", general_purpose::STANDARD.encode(&binary_data)),
        }
    };
    
    // Kryptera med nya formatet (7 delar)
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    
    let mut key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Cipher error: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Kryptera lösenordet separat med master key
    let mut pwd_salt = [0u8; 16];
    let mut pwd_nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut pwd_salt);
    rand::rngs::OsRng.fill_bytes(&mut pwd_nonce_bytes);
    
    let mut master_key = derive_key(MASTER_KEY, &pwd_salt);
    let pwd_cipher = Aes256Gcm::new_from_slice(&master_key)
        .map_err(|e| format!("Password cipher error: {}", e))?;
    let pwd_nonce = Nonce::from_slice(&pwd_nonce_bytes);
    
    let encrypted_password = pwd_cipher
        .encrypt(&pwd_nonce, password.as_bytes())
        .map_err(|e| format!("Password encryption failed: {}", e))?;
    
    master_key.zeroize();
    
    // Kryptera data
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;
    
    key.zeroize();
    
    // Spara till personer.bin (7-delars format)
    let personer_path = get_personer_path();
    let line = format!(
        "{}|{}|{}|{}|{}|{}|{}\n",
        identifier,
        general_purpose::STANDARD.encode(pwd_salt),
        general_purpose::STANDARD.encode(pwd_nonce_bytes),
        general_purpose::STANDARD.encode(encrypted_password),
        general_purpose::STANDARD.encode(salt),
        general_purpose::STANDARD.encode(nonce_bytes),
        general_purpose::STANDARD.encode(ciphertext)
    );
    
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&personer_path)
        .map_err(|_| "Skriv fel")?;
    
    file.write_all(line.as_bytes()).map_err(|_| "Skriv fel")?;
    
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// SEGMENT 3: FUNKTION 2 - LADDA UPP MAPP (BULKIMPORT)
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
enum ImportMsg {
    Progress(usize, usize, String),
    Complete(usize, usize),
    Error(String),
}

fn bulk_import_folder(folder: &str, identifier: &str, password: &str, tx: mpsc::Sender<ImportMsg>) {
    let extensions = vec!["jpg", "jpeg", "png", "gif", "webp"];
    let mut image_files = Vec::new();
    
    if let Ok(entries) = fs::read_dir(folder) {
        for entry in entries.flatten() {
            if let Ok(path) = entry.path().canonicalize() {
                if let Some(ext) = path.extension() {
                    if extensions.contains(&ext.to_string_lossy().to_lowercase().as_str()) {
                        image_files.push(path.to_string_lossy().to_string());
                    }
                }
            }
        }
    }
    
    let total = image_files.len();
    let mut success = 0;
    
    // Snabb import - bara skicka uppdatering var 5:e fil
    // ALLA BILDER FÅR SAMMA ID - då kan man radera alla med ett kommando
    for (i, file_path) in image_files.iter().enumerate() {
        if i % 5 == 0 || i == total - 1 {
            let filename = Path::new(file_path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let _ = tx.send(ImportMsg::Progress(i + 1, total, filename));
        }
        
        // Använd samma ID för alla bilder i mappen
        if encrypt_and_save_file(identifier, password, file_path).is_ok() {
            success += 1;
        }
    }
    
    let _ = tx.send(ImportMsg::Complete(success, total));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SEGMENT 4: FUNKTION 3 - SE FIL
// ═══════════════════════════════════════════════════════════════════════════════

fn decrypt_file(identifier: &str, password: &str) -> Result<String, String> {
    let personer_path = get_personer_path();
    
    if !Path::new(&personer_path).exists() {
        return Err("Databas saknas".to_string());
    }
    
    let content = fs::read_to_string(&personer_path).map_err(|_| "Läsfel")?;
    
    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        
        let parts: Vec<&str> = line.split('|').collect();
        
        // Prova nya formatet först (7 delar med separat lösenordskryptering)
        if parts.len() >= 7 && parts[0] == identifier && parts[1].len() > 20 {
            // Nya formatet (7 delar)
            let encrypted_password_salt_bytes = general_purpose::STANDARD
                .decode(parts[1])
                .map_err(|_| "Fel vid decode av pwd salt")?;
            
            let encrypted_password_nonce_bytes = general_purpose::STANDARD
                .decode(parts[2])
                .map_err(|_| "Fel vid decode av pwd nonce")?;
            
            let encrypted_password_bytes = general_purpose::STANDARD
                .decode(parts[3])
                .map_err(|_| "Fel vid decode av pwd")?;
            
            // Dekryptera lösenordet med master key
            let mut master_key = derive_key(MASTER_KEY, &encrypted_password_salt_bytes);
            let password_cipher = Aes256Gcm::new_from_slice(&master_key).map_err(|_| "Cipher fel")?;
            let password_nonce = Nonce::from_slice(&encrypted_password_nonce_bytes[..]);
            
            let password_bytes = password_cipher
                .decrypt(&password_nonce, encrypted_password_bytes.as_ref())
                .map_err(|_| "Kunde inte dekryptera lagrat lösenord - kanske fel master key?")?;
            
            master_key.zeroize();
            
            let stored_password = String::from_utf8_lossy(&password_bytes).to_string();
            
            // Verifiera lösenord
            if stored_password != password {
                return Err("Fel lösenord".to_string());
            }
            
            // Dekryptera data
            let salt_bytes = general_purpose::STANDARD.decode(parts[4]).map_err(|_| "Fel data")?;
            let nonce_bytes = general_purpose::STANDARD.decode(parts[5]).map_err(|_| "Fel data")?;
            let ciphertext = general_purpose::STANDARD.decode(parts[6]).map_err(|_| "Fel data")?;
            
            let mut key = derive_key(&stored_password, &salt_bytes);
            let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "Fel")?;
            let nonce = Nonce::from_slice(&nonce_bytes[..]);
            
            let decrypted_bytes = cipher.decrypt(&nonce, ciphertext.as_ref()).map_err(|_| "Dekrypteringsfel")?;
            
            key.zeroize();
            
            let decrypted_text = String::from_utf8_lossy(&decrypted_bytes).to_string();
            return Ok(decrypted_text);
        }
        
        // Prova gamla formatet (4 delar: ID|salt|nonce|ciphertext med PWD:hash|data inuti)
        if parts.len() >= 4 && parts[0] == identifier {
            let salt = general_purpose::STANDARD.decode(parts[1]).map_err(|_| "Fel data")?;
            let nonce_bytes = general_purpose::STANDARD.decode(parts[2]).map_err(|_| "Fel data")?;
            let ciphertext = general_purpose::STANDARD.decode(parts[3]).map_err(|_| "Fel data")?;
            
            let mut key = derive_key(password, &salt);
            let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "Fel")?;
            let nonce = Nonce::from_slice(&nonce_bytes[..]);
            
            let decrypted_bytes = cipher.decrypt(&nonce, ciphertext.as_ref()).map_err(|_| "Fel lösenord")?;
            key.zeroize();
            
            let decrypted_str = String::from_utf8_lossy(&decrypted_bytes).to_string();
            
            // Gamla formatet har PWD:hash|data
            if let Some(pipe_pos) = decrypted_str.find('|') {
                let data = &decrypted_str[pipe_pos + 1..];
                return Ok(data.to_string());
            }
            
            return Ok(decrypted_str);
        }
    }
    
    Err("ID finns inte".to_string())
}

// Uppdatera befintlig post
fn update_encrypted_file(identifier: &str, password: &str, new_content: &str) -> Result<(), String> {
    let personer_path = get_personer_path();
    
    if !Path::new(&personer_path).exists() {
        return Err("Databas saknas".to_string());
    }
    
    let content = fs::read_to_string(&personer_path).map_err(|_| "Läsfel")?;
    let mut found = false;
    let mut new_lines = Vec::new();
    
    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        
        let parts: Vec<&str> = line.split('|').collect();
        
        if parts[0] == identifier && !found {
            // Hittade posten - kryptera ny data och ersätt
            found = true;
            
            // Kryptera med nya formatet (samma som encrypt_and_save_file)
            let mut salt = [0u8; 16];
            let mut nonce_bytes = [0u8; 12];
            rand::rngs::OsRng.fill_bytes(&mut salt);
            rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
            
            let mut key = derive_key(password, &salt);
            let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "Cipher fel")?;
            let nonce = Nonce::from_slice(&nonce_bytes);
            
            let mut pwd_salt = [0u8; 16];
            let mut pwd_nonce_bytes = [0u8; 12];
            rand::rngs::OsRng.fill_bytes(&mut pwd_salt);
            rand::rngs::OsRng.fill_bytes(&mut pwd_nonce_bytes);
            
            let mut master_key = derive_key(MASTER_KEY, &pwd_salt);
            let pwd_cipher = Aes256Gcm::new_from_slice(&master_key).map_err(|_| "Fel")?;
            let pwd_nonce = Nonce::from_slice(&pwd_nonce_bytes);
            
            let encrypted_password = pwd_cipher
                .encrypt(&pwd_nonce, password.as_bytes())
                .map_err(|_| "Fel")?;
            
            master_key.zeroize();
            
            let ciphertext = cipher.encrypt(nonce, new_content.as_bytes()).map_err(|_| "Fel")?;
            key.zeroize();
            
            let new_line = format!(
                "{}|{}|{}|{}|{}|{}|{}",
                identifier,
                general_purpose::STANDARD.encode(pwd_salt),
                general_purpose::STANDARD.encode(pwd_nonce_bytes),
                general_purpose::STANDARD.encode(encrypted_password),
                general_purpose::STANDARD.encode(salt),
                general_purpose::STANDARD.encode(nonce_bytes),
                general_purpose::STANDARD.encode(ciphertext)
            );
            
            new_lines.push(new_line);
        } else {
            new_lines.push(line.to_string());
        }
    }
    
    if !found {
        return Err("ID finns inte".to_string());
    }
    
    let new_content_str = new_lines.join("\n");
    fs::write(&personer_path, format!("{}\n", new_content_str)).map_err(|_| "Skriv fel")?;
    
    Ok(())
}

// Lista alla ID-koder i databasen
fn list_all_ids() -> Vec<String> {
    let personer_path = get_personer_path();
    let mut ids = std::collections::HashSet::new();
    
    if let Ok(content) = fs::read_to_string(&personer_path) {
        for line in content.lines() {
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split('|').collect();
            if !parts.is_empty() {
                ids.insert(parts[0].to_string());
            }
        }
    }
    
    let mut unique_ids: Vec<String> = ids.into_iter().collect();
    unique_ids.sort();
    unique_ids
}

// ═══════════════════════════════════════════════════════════════════════════════
// SEGMENT 5: FUNKTION 4 - SE GALLERI
// ═══════════════════════════════════════════════════════════════════════════════

// Dekryptera ALLA poster med samma ID (för galleri)
fn decrypt_all_with_id(identifier: &str, password: &str) -> Result<Vec<String>, String> {
    let personer_path = get_personer_path();
    
    if !Path::new(&personer_path).exists() {
        return Err("Databas saknas".to_string());
    }
    
    let content = fs::read_to_string(&personer_path).map_err(|_| "Läsfel")?;
    let mut decrypted_items = Vec::new();
    
    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        
        let parts: Vec<&str> = line.split('|').collect();
        
        // Kolla om denna rad matchar vårt ID
        if parts.is_empty() || parts[0] != identifier {
            continue;
        }
        
        // Prova nya formatet först (7 delar)
        if parts.len() >= 7 && parts[1].len() > 20 {
            if let Ok(decrypted) = decrypt_line_new_format(&parts, password) {
                decrypted_items.push(decrypted);
                continue;
            }
        }
        
        // Prova gamla formatet (4 delar)
        if parts.len() >= 4 {
            if let Ok(decrypted) = decrypt_line_old_format(&parts, password) {
                decrypted_items.push(decrypted);
            }
        }
    }
    
    if decrypted_items.is_empty() {
        Err("ID finns inte eller fel lösenord".to_string())
    } else {
        Ok(decrypted_items)
    }
}

// Hjälpfunktioner för dekryptering
fn decrypt_line_new_format(parts: &[&str], password: &str) -> Result<String, String> {
    let encrypted_password_salt_bytes = general_purpose::STANDARD.decode(parts[1]).map_err(|_| "Fel")?;
    let encrypted_password_nonce_bytes = general_purpose::STANDARD.decode(parts[2]).map_err(|_| "Fel")?;
    let encrypted_password_bytes = general_purpose::STANDARD.decode(parts[3]).map_err(|_| "Fel")?;
    
    let mut master_key = derive_key(MASTER_KEY, &encrypted_password_salt_bytes);
    let password_cipher = Aes256Gcm::new_from_slice(&master_key).map_err(|_| "Fel")?;
    let password_nonce = Nonce::from_slice(&encrypted_password_nonce_bytes[..]);
    
    let password_bytes = password_cipher.decrypt(&password_nonce, encrypted_password_bytes.as_ref()).map_err(|_| "Fel")?;
    master_key.zeroize();
    
    let stored_password = String::from_utf8_lossy(&password_bytes).to_string();
    if stored_password != password {
        return Err("Fel lösenord".to_string());
    }
    
    let salt_bytes = general_purpose::STANDARD.decode(parts[4]).map_err(|_| "Fel")?;
    let nonce_bytes = general_purpose::STANDARD.decode(parts[5]).map_err(|_| "Fel")?;
    let ciphertext = general_purpose::STANDARD.decode(parts[6]).map_err(|_| "Fel")?;
    
    let mut key = derive_key(&stored_password, &salt_bytes);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "Fel")?;
    let nonce = Nonce::from_slice(&nonce_bytes[..]);
    
    let decrypted_bytes = cipher.decrypt(&nonce, ciphertext.as_ref()).map_err(|_| "Fel")?;
    key.zeroize();
    
    Ok(String::from_utf8_lossy(&decrypted_bytes).to_string())
}

fn decrypt_line_old_format(parts: &[&str], password: &str) -> Result<String, String> {
    let salt = general_purpose::STANDARD.decode(parts[1]).map_err(|_| "Fel")?;
    let nonce_bytes = general_purpose::STANDARD.decode(parts[2]).map_err(|_| "Fel")?;
    let ciphertext = general_purpose::STANDARD.decode(parts[3]).map_err(|_| "Fel")?;
    
    let mut key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "Fel")?;
    let nonce = Nonce::from_slice(&nonce_bytes[..]);
    
    let decrypted_bytes = cipher.decrypt(&nonce, ciphertext.as_ref()).map_err(|_| "Fel")?;
    key.zeroize();
    
    let decrypted_str = String::from_utf8_lossy(&decrypted_bytes).to_string();
    
    if let Some(pipe_pos) = decrypted_str.find('|') {
        Ok(decrypted_str[pipe_pos + 1..].to_string())
    } else {
        Ok(decrypted_str)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SEGMENT 6: FUNKTION 5 - RADERA ID-KOD
// ═══════════════════════════════════════════════════════════════════════════════

fn delete_id(identifier: &str) -> Result<(), String> {
    let personer_path = get_personer_path();
    
    if !Path::new(&personer_path).exists() {
        return Err(format!("Databasen '{}' saknas", personer_path));
    }
    
    let content = fs::read_to_string(&personer_path)
        .map_err(|e| format!("Kunde inte läsa {}: {}", personer_path, e))?;
    
    let new_content: Vec<String> = content
        .lines()
        .filter(|line| {
            if line.is_empty() {
                return false;
            }
            let parts: Vec<&str> = line.split('|').collect();
            !parts.is_empty() && parts[0] != identifier
        })
        .map(|s| s.to_string())
        .collect();
    
    let new_content_str = new_content.join("\n");
    if !new_content_str.is_empty() {
        fs::write(&personer_path, format!("{}\n", new_content_str))
            .map_err(|e| format!("Kunde inte skriva till {}: {}", personer_path, e))?;
    } else {
        fs::write(&personer_path, "")
            .map_err(|e| format!("Kunde inte skriva till {}: {}", personer_path, e))?;
    }
    
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// SEGMENT 7: FUNKTION 6 - KONTROLLERA AI (EXIF-DATA)
// ═══════════════════════════════════════════════════════════════════════════════

// Använder detector.rs för att kontrollera EXIF-data

// ═══════════════════════════════════════════════════════════════════════════════
// SEGMENT 8: FUNKTION 7 - DESIGNA DATABASEN
// ═══════════════════════════════════════════════════════════════════════════════

// Använder desig.rs för att ladda och applicera teman

// ═══════════════════════════════════════════════════════════════════════════════
// SEGMENT 9: GUI - HUVUDSTRUKTUR
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug, PartialEq)]
enum AppMode {
    Welcome,
    UploadFile,
    UploadFolder,
    ViewFile,
    ViewGallery,
    DeleteId,
    CheckAI,
    Design,
}

#[derive(Clone, Debug)]
struct GalleryEntry {
    namn: String,
    base64: Option<String>,
}

struct MyApp {
    mode: AppMode,
    identifier_input: String,
    password_input: String,
    file_path_input: String,
    folder_path_input: String,
    message: String,
    decrypted_content: String,
    entries: Vec<GalleryEntry>,
    texture_cache: std::collections::HashMap<String, egui::TextureHandle>,
    texture_lru: std::collections::VecDeque<String>,
    import_rx: Option<Receiver<ImportMsg>>,
    import_progress_current: usize,
    import_progress_total: usize,
    loading_status: String,
    ai_scan_results: Vec<String>,
    table_data: Vec<Vec<String>>,
    table_edit_mode: bool,
    image_description: String,
    image_edit_mode: bool,
    sort_column: Option<usize>,
    sort_ascending: bool,
    theme_config: desig::ThemeConfig,
    design_modified: bool,
}

impl Default for MyApp {
    fn default() -> Self {
        let theme_config = desig::load_theme_config()
            .unwrap_or_else(|_| desig::get_default_theme());
            
        Self {
            mode: AppMode::Welcome,
            identifier_input: String::new(),
            password_input: String::new(),
            file_path_input: String::new(),
            folder_path_input: String::new(),
            message: String::new(),
            decrypted_content: String::new(),
            entries: Vec::new(),
            texture_cache: std::collections::HashMap::new(),
            texture_lru: std::collections::VecDeque::new(),
            import_rx: None,
            import_progress_current: 0,
            import_progress_total: 0,
            loading_status: String::new(),
            ai_scan_results: Vec::new(),
            table_data: Vec::new(),
            table_edit_mode: false,
            image_description: String::new(),
            image_edit_mode: false,
            sort_column: None,
            sort_ascending: true,
            theme_config,
            design_modified: false,
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Applicera tema
        let theme = load_theme_from_yaml();
        apply_theme(ctx, &theme);
        
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(20.0);
            
            match self.mode {
                AppMode::Welcome => self.show_welcome(ui),
                AppMode::UploadFile => self.show_upload_file(ui, ctx),
                AppMode::UploadFolder => self.show_upload_folder(ui, ctx),
                AppMode::ViewFile => self.show_view_file(ui, ctx),
                AppMode::ViewGallery => self.show_view_gallery(ui, ctx),
                AppMode::DeleteId => self.show_delete_id(ui),
                AppMode::CheckAI => self.show_check_ai(ui),
                AppMode::Design => self.show_design(ui),
            }
        });
    }
}

impl MyApp {
    // ═══════════════════════════════════════════════════════════════════════════
    // VÄLKOMSTSKÄRM MED 7 KNAPPAR
    // ═══════════════════════════════════════════════════════════════════════════
    
    fn show_welcome(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.label(RichText::new("🔐 AI DATABASEN").size(32.0).strong());
            ui.add_space(10.0);
            ui.label(RichText::new("Krypterad databas med 7 huvudfunktioner")
                .size(14.0)
                .color(egui::Color32::GRAY));
            ui.add_space(40.0);
            
            // KNAPP 1: Ladda upp fil
            if ui.add_sized([400.0, 60.0], egui::Button::new(
                RichText::new("📄 1. Ladda upp fil").size(16.0)
            )).clicked() {
                self.mode = AppMode::UploadFile;
                self.reset_inputs();
            }
            
            ui.add_space(10.0);
            
            // KNAPP 2: Ladda upp mapp
            if ui.add_sized([400.0, 60.0], egui::Button::new(
                RichText::new("📁 2. Ladda upp mapp").size(16.0)
            )).clicked() {
                self.mode = AppMode::UploadFolder;
                self.reset_inputs();
            }
            
            ui.add_space(10.0);
            
            // KNAPP 3: Se fil
            if ui.add_sized([400.0, 60.0], egui::Button::new(
                RichText::new("👁️ 3. Se fil").size(16.0)
            )).clicked() {
                self.mode = AppMode::ViewFile;
                self.reset_inputs();
            }
            
            ui.add_space(10.0);
            
            // KNAPP 4: Se galleri
            if ui.add_sized([400.0, 60.0], egui::Button::new(
                RichText::new("🖼️ 4. Se galleri").size(16.0)
            )).clicked() {
                self.mode = AppMode::ViewGallery;
                self.reset_inputs();
            }
            
            ui.add_space(10.0);
            
            // KNAPP 5: Radera ID-kod
            if ui.add_sized([400.0, 60.0], egui::Button::new(
                RichText::new("🗑️ 5. Radera ID-kod").size(16.0)
            )).clicked() {
                self.mode = AppMode::DeleteId;
                self.reset_inputs();
            }
            
            ui.add_space(10.0);
            
            // KNAPP 6: Kontrollera AI
            if ui.add_sized([400.0, 60.0], egui::Button::new(
                RichText::new("🤖 6. Kontrollera AI").size(16.0)
            )).clicked() {
                self.mode = AppMode::CheckAI;
                self.reset_inputs();
            }
            
            ui.add_space(10.0);
            
            // KNAPP 7: Designa databasen
            if ui.add_sized([400.0, 60.0], egui::Button::new(
                RichText::new("🎨 7. Designa databasen").size(16.0)
            )).clicked() {
                self.mode = AppMode::Design;
                self.reset_inputs();
            }
            
            // Visa ID-koder i databasen
            ui.add_space(40.0);
            ui.separator();
            ui.add_space(20.0);
            
            ui.label(RichText::new("📋 ID-koder i databasen").size(16.0).strong());
            ui.add_space(10.0);
            
            let ids = list_all_ids();
            if ids.is_empty() {
                ui.label(RichText::new("Databasen är tom")
                    .size(13.0)
                    .color(egui::Color32::GRAY));
            } else {
                ui.label(RichText::new(format!("Totalt: {} poster", ids.len()))
                    .size(12.0)
                    .color(egui::Color32::from_rgb(100, 200, 255)));
                ui.add_space(10.0);
                
                // Snygg tabell med scroll för ID-koder
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(25, 25, 35))
                    .stroke(egui::Stroke::new(1.5, egui::Color32::from_rgb(60, 60, 80)))
                    .rounding(8.0)
                    .inner_margin(15.0)
                    .show(ui, |ui| {
                        ui.set_max_width(600.0);
                        ScrollArea::vertical()
                            .max_height(300.0)
                            .auto_shrink([false, true])
                            .show(ui, |ui| {
                                for (i, id) in ids.iter().enumerate() {
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new(format!("{}.", i + 1))
                                            .size(11.0)
                                            .color(egui::Color32::GRAY));
                                        ui.label(RichText::new(id)
                                            .size(13.0)
                                            .color(egui::Color32::from_rgb(150, 220, 255)));
                                    });
                                    ui.add_space(3.0);
                                }
                            });
                    });
            }
        });
    }
    
    fn reset_inputs(&mut self) {
        self.identifier_input.clear();
        self.password_input.clear();
        self.file_path_input.clear();
        self.folder_path_input.clear();
        self.message.clear();
        self.decrypted_content.clear();
        self.entries.clear();
        self.ai_scan_results.clear();
        self.table_data.clear();
        self.table_edit_mode = false;
        self.image_description.clear();
        self.image_edit_mode = false;
        self.sort_column = None;
        self.sort_ascending = true;
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // FUNKTION 1: LADDA UPP FIL
    // ═══════════════════════════════════════════════════════════════════════════
    
    fn show_upload_file(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context) {
        ui.vertical_centered(|ui| {
            ui.add_space(30.0);
            ui.label(RichText::new("📄 Ladda upp fil").size(26.0).strong()
                .color(egui::Color32::from_rgb(100, 200, 255)));
            ui.add_space(30.0);
            
            // Snygg centrerad tabell
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(25, 25, 35))
                .stroke(egui::Stroke::new(2.0, egui::Color32::from_rgb(60, 60, 80)))
                .rounding(10.0)
                .inner_margin(30.0)
                .show(ui, |ui| {
                    ui.set_max_width(500.0);
                    
                    ui.label(RichText::new("ID-kod:").size(14.0).strong());
                    ui.add_space(5.0);
                    ui.add_sized([450.0, 30.0], egui::TextEdit::singleline(&mut self.identifier_input));
                    ui.add_space(15.0);
                    
                    ui.label(RichText::new("Lösenord:").size(14.0).strong());
                    ui.add_space(5.0);
                    ui.add_sized([450.0, 30.0], egui::TextEdit::singleline(&mut self.password_input).password(true));
                    ui.add_space(15.0);
                    
                    ui.label(RichText::new("Filväg:").size(14.0).strong());
                    ui.add_space(5.0);
                    ui.add_sized([450.0, 30.0], egui::TextEdit::singleline(&mut self.file_path_input));
                    ui.add_space(10.0);
                    
                    if ui.add_sized([200.0, 35.0], egui::Button::new("📂 Välj fil")).clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.file_path_input = path.to_string_lossy().to_string();
                        }
                    }
                    
                    ui.add_space(25.0);
                    ui.separator();
                    ui.add_space(15.0);
                    
                    ui.horizontal(|ui| {
                        if ui.add_sized([130.0, 40.0], egui::Button::new("⬅️ Tillbaka")).clicked() {
                            self.mode = AppMode::Welcome;
                        }
                        ui.add_space(20.0);
                        if ui.add_sized([250.0, 40.0], egui::Button::new("🔒 Kryptera & Spara")).clicked() {
                            if !self.identifier_input.is_empty() && !self.password_input.is_empty() && !self.file_path_input.is_empty() {
                                match encrypt_and_save_file(&self.identifier_input, &self.password_input, &self.file_path_input) {
                                    Ok(_) => {
                                        self.message = format!("✅ Filen har krypterats och sparats med ID: {}", self.identifier_input);
                                    }
                                    Err(e) => {
                                        self.message = format!("❌ Fel: {}", e);
                                    }
                                }
                            } else {
                                self.message = "❌ Fyll i alla fält".to_string();
                            }
                        }
                    });
                    
                    if !self.message.is_empty() {
                        ui.add_space(20.0);
                        ui.label(RichText::new(&self.message).size(13.0));
                    }
                });
        });
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // FUNKTION 2: LADDA UPP MAPP
    // ═══════════════════════════════════════════════════════════════════════════
    
    fn show_upload_folder(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.vertical_centered(|ui| {
            ui.add_space(30.0);
            ui.label(RichText::new("📁 Ladda upp mapp").size(26.0).strong()
                .color(egui::Color32::from_rgb(100, 200, 255)));
            ui.add_space(30.0);
            
            // Snygg centrerad tabell
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(25, 25, 35))
                .stroke(egui::Stroke::new(2.0, egui::Color32::from_rgb(60, 60, 80)))
                .rounding(10.0)
                .inner_margin(30.0)
                .show(ui, |ui| {
                    ui.set_max_width(500.0);
                    
                    ui.label(RichText::new("ID-kod (för alla bilder i mappen):").size(14.0).strong());
                    ui.add_space(5.0);
                    ui.add_sized([450.0, 30.0], egui::TextEdit::singleline(&mut self.identifier_input));
                    ui.add_space(15.0);
                    
                    ui.label(RichText::new("Lösenord:").size(14.0).strong());
                    ui.add_space(5.0);
                    ui.add_sized([450.0, 30.0], egui::TextEdit::singleline(&mut self.password_input).password(true));
                    ui.add_space(15.0);
                    
                    ui.label(RichText::new("Mapp:").size(14.0).strong());
                    ui.add_space(5.0);
                    ui.add_sized([450.0, 30.0], egui::TextEdit::singleline(&mut self.folder_path_input));
                    ui.add_space(10.0);
                    
                    if ui.add_sized([200.0, 35.0], egui::Button::new("📂 Välj mapp")).clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_folder() {
                            self.folder_path_input = path.to_string_lossy().to_string();
                        }
                    }
                    
                    // Visa progress
                    if let Some(rx) = &self.import_rx {
                        match rx.try_recv() {
                            Ok(ImportMsg::Progress(current, total, filename)) => {
                                self.import_progress_current = current;
                                self.import_progress_total = total;
                                self.loading_status = format!("Bearbetar: {}", filename);
                                ctx.request_repaint();
                            }
                            Ok(ImportMsg::Complete(success, total)) => {
                                self.message = format!("✅ Klar! {} av {} bilder importerade", success, total);
                                self.import_rx = None;
                            }
                            Ok(ImportMsg::Error(msg)) => {
                                self.message = format!("❌ {}", msg);
                                self.import_rx = None;
                            }
                            Err(_) => {}
                        }
                    }
                    
                    if self.import_rx.is_some() {
                        ui.add_space(15.0);
                        ui.label(RichText::new(&self.loading_status).size(13.0).color(egui::Color32::YELLOW));
                        ui.label(RichText::new(format!("📊 {}/{}", self.import_progress_current, self.import_progress_total))
                            .size(14.0).strong());
                    }
                    
                    ui.add_space(25.0);
                    ui.separator();
                    ui.add_space(15.0);
                    
                    ui.horizontal(|ui| {
                        if ui.add_sized([130.0, 40.0], egui::Button::new("⬅️ Tillbaka")).clicked() {
                            self.mode = AppMode::Welcome;
                        }
                        ui.add_space(20.0);
                        if ui.add_sized([250.0, 40.0], egui::Button::new("📥 Importera")).clicked() && self.import_rx.is_none() {
                            if !self.identifier_input.is_empty() && !self.password_input.is_empty() && !self.folder_path_input.is_empty() {
                                let folder = self.folder_path_input.clone();
                                let identifier = self.identifier_input.clone();
                                let password = self.password_input.clone();
                                
                                let (tx, rx) = mpsc::channel::<ImportMsg>();
                                self.import_rx = Some(rx);
                                
                                thread::spawn(move || {
                                    bulk_import_folder(&folder, &identifier, &password, tx);
                                });
                            } else {
                                self.message = "❌ Fyll i alla fält".to_string();
                            }
                        }
                    });
                    
                    if !self.message.is_empty() {
                        ui.add_space(20.0);
                        ui.label(RichText::new(&self.message).size(13.0));
                    }
                });
        });
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // FUNKTION 3: SE FIL
    // ═══════════════════════════════════════════════════════════════════════════
    
    fn show_view_file(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.vertical_centered(|ui| {
            ui.add_space(30.0);
            ui.label(RichText::new("👁️ Se fil").size(26.0).strong()
                .color(egui::Color32::from_rgb(100, 200, 255)));
            ui.add_space(30.0);
            
            // Snygg centrerad tabell för input
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(25, 25, 35))
                .stroke(egui::Stroke::new(2.0, egui::Color32::from_rgb(60, 60, 80)))
                .rounding(10.0)
                .inner_margin(30.0)
                .show(ui, |ui| {
                    ui.set_max_width(500.0);
                    
                    ui.label(RichText::new("ID-kod:").size(14.0).strong());
                    ui.add_space(5.0);
                    ui.add_sized([450.0, 30.0], egui::TextEdit::singleline(&mut self.identifier_input));
                    ui.add_space(15.0);
                    
                    ui.label(RichText::new("Lösenord:").size(14.0).strong());
                    ui.add_space(5.0);
                    ui.add_sized([450.0, 30.0], egui::TextEdit::singleline(&mut self.password_input).password(true));
                    ui.add_space(25.0);
                    ui.separator();
                    ui.add_space(15.0);
                    
                    ui.horizontal(|ui| {
                        if ui.add_sized([130.0, 40.0], egui::Button::new("⬅️ Tillbaka")).clicked() {
                            self.mode = AppMode::Welcome;
                            self.decrypted_content.clear();
                            self.entries.clear();
                        }
                        ui.add_space(20.0);
                        if ui.add_sized([250.0, 40.0], egui::Button::new("🔓 Dekryptera")).clicked() {
                    self.entries.clear(); // Rensa tidigare resultat
                    if !self.identifier_input.is_empty() && !self.password_input.is_empty() {
                        match decrypt_file(&self.identifier_input, &self.password_input) {
                            Ok(content) => {
                                self.decrypted_content = content.clone();
                                
                                // Parse content
                                if content.starts_with("IMAGE:") {
                                    let img_content = &content[6..];
                                    let parts: Vec<&str> = img_content.split('|').collect();
                                    if parts.len() >= 2 {
                                        self.entries.push(GalleryEntry {
                                            namn: parts[0].to_string(),
                                            base64: Some(parts[1].to_string()),
                                        });
                                        // Ladda beskrivning om det finns
                                        if parts.len() >= 3 && !parts[2].is_empty() {
                                            self.image_description = parts[2].to_string();
                                        }
                                        self.message = "✅ Bild dekrypterad!".to_string();
                                    }
                                } else if content.starts_with("TEXT:") {
                                    self.message = "✅ Text dekrypterad!".to_string();
                                } else {
                                    self.message = "✅ Dekrypterat!".to_string();
                                }
                            }
                            Err(e) => {
                                self.message = format!("❌ {}", e);
                                self.decrypted_content.clear();
                            }
                        }
                    } else {
                        self.message = "❌ Ange ID och lösenord".to_string();
                    }
                        }
                    });
                    
                    if !self.message.is_empty() {
                        ui.add_space(20.0);
                        ui.label(RichText::new(&self.message).size(13.0));
                    }
                });
            
            // Visa dekrypterat innehåll utanför tabellen
            if !self.entries.is_empty() {
                ui.add_space(20.0);
                
                ui.label(RichText::new("🖼️ Bildfil").size(16.0));
                ui.add_space(10.0);
                
                // Visa och redigera bildbeskrivning
                ui.horizontal(|ui| {
                    ui.label("📝 Bildtext:");
                    if !self.image_edit_mode {
                        if ui.button("✏️ Redigera").clicked() {
                            self.image_edit_mode = true;
                        }
                    } else {
                        if ui.button("✅ Spara").clicked() {
                            // Spara ny beskrivning
                            if let Some(entry) = self.entries.first() {
                                if let Some(base64_data) = &entry.base64 {
                                    let new_content = format!("IMAGE:{}|{}|{}", 
                                        entry.namn, base64_data, self.image_description);
                                    
                                    match update_encrypted_file(&self.identifier_input, &self.password_input, &new_content) {
                                        Ok(_) => {
                                            self.message = "✅ Bildtext sparad!".to_string();
                                            self.image_edit_mode = false;
                                        }
                                        Err(e) => {
                                            self.message = format!("❌ {}", e);
                                        }
                                    }
                                }
                            }
                        }
                        if ui.button("❌ Avbryt").clicked() {
                            self.image_edit_mode = false;
                        }
                    }
                });
                
                ui.add_space(5.0);
                
                if self.image_edit_mode {
                    ui.text_edit_multiline(&mut self.image_description);
                } else {
                    if !self.image_description.is_empty() {
                        ui.label(&self.image_description);
                    } else {
                        ui.label(RichText::new("(ingen bildtext)").color(egui::Color32::GRAY));
                    }
                }
                
                ui.add_space(15.0);
                
                // Visa bilden
                for entry in &self.entries {
                    if let Some(base64_data) = &entry.base64 {
                        if let Ok(img_bytes) = general_purpose::STANDARD.decode(base64_data) {
                            if let Ok(img) = image::load_from_memory(&img_bytes) {
                                let rgba = img.to_rgba8();
                                let size = [rgba.width() as _, rgba.height() as _];
                                let pixels = rgba.as_flat_samples();
                                
                                let color_image = egui::ColorImage::from_rgba_unmultiplied(
                                    size,
                                    pixels.as_slice(),
                                );
                                
                                let texture_id = format!("{}_{}", self.identifier_input, entry.namn);
                                let texture = self.texture_cache.entry(texture_id.clone())
                                    .or_insert_with(|| ctx.load_texture(&texture_id, color_image, Default::default()));
                                
                                ui.image((texture.id(), egui::vec2(400.0, 400.0)));
                                ui.label(RichText::new(&entry.namn).size(12.0).color(egui::Color32::GRAY));
                            }
                        }
                    }
                }
            } else if !self.decrypted_content.is_empty() && !self.decrypted_content.starts_with("IMAGE:") {
                ui.add_space(20.0);
                
                // Hantera TEXT:-filer
                if self.decrypted_content.starts_with("TEXT:") {
                    let text_content = &self.decrypted_content[5..]; // Hoppa över "TEXT:"
                    
                    // Försök detektera tabell
                    if self.table_data.is_empty() {
                        if let Some(parsed) = parse_table_data(text_content) {
                            self.table_data = parsed;
                        }
                    }
                    
                    // Visa tabell om det finns
                    if !self.table_data.is_empty() {
                        // Sortera data om en kolumn är vald
                        if let Some(col_idx) = self.sort_column {
                            if col_idx < self.table_data[0].len() {
                                // Sortera ALLA rader (inklusive första) i bokstavsordning
                                self.table_data.sort_by(|a, b| {
                                    let val_a = a.get(col_idx).map(|s| s.as_str()).unwrap_or("");
                                    let val_b = b.get(col_idx).map(|s| s.as_str()).unwrap_or("");
                                    
                                    // Bokstavsordning (case-insensitive för bättre sortering)
                                    let val_a_lower = val_a.to_lowercase();
                                    let val_b_lower = val_b.to_lowercase();
                                    
                                    if self.sort_ascending {
                                        val_a_lower.cmp(&val_b_lower)
                                    } else {
                                        val_b_lower.cmp(&val_a_lower)
                                    }
                                });
                                
                                self.sort_column = None; // Rensa efter sortering
                            }
                        }
                        
                        // Centrerad tabellvisning med snygg design
                        ui.vertical_centered(|ui| {
                            ui.label(RichText::new("📊 Tabelldata").size(18.0).strong()
                                .color(egui::Color32::from_rgb(100, 200, 255)));
                            ui.add_space(15.0);
                            
                            // Redigeringsknapp
                            if !self.table_edit_mode {
                                if ui.add_sized([200.0, 35.0], egui::Button::new("✏️ Redigera tabell")).clicked() {
                                    self.table_edit_mode = true;
                                }
                            } else {
                                ui.horizontal(|ui| {
                                    if ui.add_sized([120.0, 35.0], egui::Button::new("✅ Klar")).clicked() {
                                        self.table_edit_mode = false;
                                    }
                                    ui.add_space(10.0);
                                    if ui.add_sized([140.0, 35.0], egui::Button::new("➕ Lägg till rad")).clicked() {
                                        // Lägg till en ny tom rad med samma antal kolumner
                                        if !self.table_data.is_empty() {
                                            let num_cols = self.table_data[0].len();
                                            let new_row = vec![String::new(); num_cols];
                                            self.table_data.push(new_row);
                                        }
                                    }
                                    ui.add_space(10.0);
                                    if ui.add_sized([180.0, 35.0], egui::Button::new("💾 Spara ändringar")).clicked() {
                                        // Konvertera tabell tillbaka till text
                                        let mut new_text = String::new();
                                        for row in &self.table_data {
                                            new_text.push_str(&row.join("  "));
                                            new_text.push('\n');
                                        }
                                        
                                        // Kryptera och spara
                                        let plaintext = format!("TEXT:{}", new_text);
                                        match update_encrypted_file(&self.identifier_input, &self.password_input, &plaintext) {
                                            Ok(_) => {
                                                self.message = "✅ Ändringar sparade!".to_string();
                                                self.table_edit_mode = false;
                                            }
                                            Err(e) => {
                                                self.message = format!("❌ {}", e);
                                            }
                                        }
                                    }
                                });
                            }
                            
                            ui.add_space(20.0);
                            
                            // Snygg ram runt tabellen
                            egui::Frame::none()
                                .fill(egui::Color32::from_rgb(25, 25, 35))
                                .stroke(egui::Stroke::new(2.0, egui::Color32::from_rgb(60, 60, 80)))
                                .rounding(10.0)
                                .inner_margin(20.0)
                                .show(ui, |ui| {
                                    // Visa tabell med scrollbar
                                    ScrollArea::vertical()
                                        .max_height(500.0)
                                        .auto_shrink([false, true])
                                        .show(ui, |ui| {
                                            ScrollArea::horizontal()
                                                .auto_shrink([false, false])
                                                .show(ui, |ui| {
                                                    egui::Grid::new("text_table")
                                                        .striped(true)
                                                        .spacing([15.0, 8.0])
                                                        .min_col_width(100.0)
                                                        .show(ui, |ui| {
                                                            // Skapa kolumnrubriker om de inte finns
                                                            let num_columns = self.table_data[0].len();
                                                            
                                                            // Rita kolumnrubriker som klickbara knappar
                                                            for col_idx in 0..num_columns {
                                                                let header_text = format!("Kolumn{}", col_idx + 1);
                                                                let sort_indicator = if self.sort_column == Some(col_idx) {
                                                                    if self.sort_ascending { " ▲" } else { " ▼" }
                                                                } else {
                                                                    ""
                                                                };
                                                                
                                                                if ui.add_sized([120.0, 30.0], 
                                                                    egui::Button::new(RichText::new(format!("{}{}", header_text, sort_indicator))
                                                                        .strong()
                                                                        .size(14.0)
                                                                        .color(egui::Color32::from_rgb(150, 220, 255)))
                                                                ).clicked() {
                                                                    // Växla sortering
                                                                    if self.sort_column == Some(col_idx) {
                                                                        self.sort_ascending = !self.sort_ascending;
                                                                    } else {
                                                                        self.sort_column = Some(col_idx);
                                                                        self.sort_ascending = true;
                                                                    }
                                                                }
                                                            }
                                                            // Extra kolumn för radera-knapp i redigeringsläge
                                                            if self.table_edit_mode {
                                                                ui.label(RichText::new("🗑️ Ta bort")
                                                                    .strong()
                                                                    .size(14.0)
                                                                    .color(egui::Color32::from_rgb(255, 150, 150)));
                                                            }
                                                            ui.end_row();
                                                            
                                                            // Rita datarader
                                                            let mut row_to_delete: Option<usize> = None;
                                                            for (row_idx, row) in self.table_data.iter_mut().enumerate() {
                                                                for (_col_idx, cell) in row.iter_mut().enumerate() {
                                                                    if self.table_edit_mode {
                                                                        ui.add_sized([120.0, 25.0], egui::TextEdit::singleline(cell));
                                                                    } else {
                                                                        ui.label(RichText::new(cell.as_str())
                                                                            .size(13.0)
                                                                            .color(egui::Color32::from_rgb(220, 220, 240)));
                                                                    }
                                                                }
                                                                
                                                                // Radera-knapp i redigeringsläge
                                                                if self.table_edit_mode {
                                                                    if ui.add_sized([60.0, 25.0], 
                                                                        egui::Button::new(RichText::new("🗑️")
                                                                            .color(egui::Color32::from_rgb(255, 100, 100)))
                                                                    ).clicked() {
                                                                        row_to_delete = Some(row_idx);
                                                                    }
                                                                }
                                                                
                                                                ui.end_row();
                                                            }
                                                            
                                                            // Ta bort rad om en markerades för borttagning
                                                            if let Some(idx) = row_to_delete {
                                                                if self.table_data.len() > 1 {
                                                                    self.table_data.remove(idx);
                                                                } else {
                                                                    self.message = "❌ Kan inte ta bort sista raden".to_string();
                                                                }
                                                            }
                                                        });
                                                });
                                        });
                                });
                        });
                    } else {
                        // Visa som vanlig text - med snygg centrerad design
                        ui.vertical_centered(|ui| {
                            ui.label(RichText::new("📝 Textfil").size(18.0).strong()
                                .color(egui::Color32::from_rgb(100, 200, 255)));
                            ui.add_space(15.0);
                            
                            // Snygg ram runt texten (samma stil som tabellen)
                            egui::Frame::none()
                                .fill(egui::Color32::from_rgb(25, 25, 35))
                                .stroke(egui::Stroke::new(2.0, egui::Color32::from_rgb(60, 60, 80)))
                                .rounding(10.0)
                                .inner_margin(20.0)
                                .show(ui, |ui| {
                                    ui.set_max_width(900.0);
                                    ScrollArea::vertical()
                                        .max_height(500.0)
                                        .auto_shrink([false, true])
                                        .show(ui, |ui| {
                                            ui.label(RichText::new(text_content)
                                                .size(13.0)
                                                .color(egui::Color32::from_rgb(220, 220, 240)));
                                        });
                                });
                        });
                    }
                } else {
                    // Annan typ av data - med snygg centrerad design
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("📄 Dekrypterat innehåll").size(18.0).strong()
                            .color(egui::Color32::from_rgb(100, 200, 255)));
                        ui.add_space(15.0);
                        
                        // Snygg ram runt innehållet (samma stil som tabellen)
                        egui::Frame::none()
                            .fill(egui::Color32::from_rgb(25, 25, 35))
                            .stroke(egui::Stroke::new(2.0, egui::Color32::from_rgb(60, 60, 80)))
                            .rounding(10.0)
                            .inner_margin(20.0)
                            .show(ui, |ui| {
                                ui.set_max_width(900.0);
                                ScrollArea::vertical()
                                    .max_height(500.0)
                                    .auto_shrink([false, true])
                                    .show(ui, |ui| {
                                        ui.label(RichText::new(&self.decrypted_content)
                                            .size(13.0)
                                            .color(egui::Color32::from_rgb(220, 220, 240)));
                                    });
                            });
                    });
                }
            }
        });
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // FUNKTION 4: SE GALLERI
    // ═══════════════════════════════════════════════════════════════════════════
    
    fn show_view_gallery(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.vertical_centered(|ui| {
            ui.add_space(30.0);
            ui.label(RichText::new("🖼️ Se galleri").size(26.0).strong()
                .color(egui::Color32::from_rgb(100, 200, 255)));
            ui.add_space(30.0);
            
            // Snygg centrerad tabell för input
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(25, 25, 35))
                .stroke(egui::Stroke::new(2.0, egui::Color32::from_rgb(60, 60, 80)))
                .rounding(10.0)
                .inner_margin(30.0)
                .show(ui, |ui| {
                    ui.set_max_width(500.0);
                    
                    ui.label(RichText::new("ID-kod:").size(14.0).strong());
                    ui.add_space(5.0);
                    ui.add_sized([450.0, 30.0], egui::TextEdit::singleline(&mut self.identifier_input));
                    ui.add_space(15.0);
                    
                    ui.label(RichText::new("Lösenord:").size(14.0).strong());
                    ui.add_space(5.0);
                    ui.add_sized([450.0, 30.0], egui::TextEdit::singleline(&mut self.password_input).password(true));
                    ui.add_space(25.0);
                    ui.separator();
                    ui.add_space(15.0);
                    
                    ui.horizontal(|ui| {
                        if ui.add_sized([130.0, 40.0], egui::Button::new("⬅️ Tillbaka")).clicked() {
                            self.mode = AppMode::Welcome;
                            self.entries.clear();
                        }
                        ui.add_space(20.0);
                        if ui.add_sized([250.0, 40.0], egui::Button::new("🔓 Visa galleri")).clicked() {
                    if !self.identifier_input.is_empty() && !self.password_input.is_empty() {
                        self.entries.clear();
                        
                        // Hämta ALLA poster med detta ID
                        match decrypt_all_with_id(&self.identifier_input, &self.password_input) {
                            Ok(decrypted_items) => {
                                for (i, content) in decrypted_items.iter().enumerate() {
                                    if content.starts_with("IMAGE:") {
                                        let img_content = &content[6..];
                                        let parts: Vec<&str> = img_content.split('|').collect();
                                        if parts.len() >= 2 {
                                            self.entries.push(GalleryEntry {
                                                namn: format!("{}_{}", parts[0], i + 1),
                                                base64: Some(parts[1].to_string()),
                                            });
                                        }
                                    }
                                }
                                
                                if self.entries.is_empty() {
                                    self.message = "❌ Inga bilder hittades".to_string();
                                } else {
                                    self.message = format!("✅ Hittade {} bilder", self.entries.len());
                                }
                            }
                            Err(e) => {
                                self.message = format!("❌ {}", e);
                            }
                        }
                    } else {
                        self.message = "❌ Fyll i alla fält".to_string();
                    }
                        }
                    });
                    
                    if !self.message.is_empty() {
                        ui.add_space(20.0);
                        ui.label(RichText::new(&self.message).size(13.0));
                    }
                });
            
            // Visa galleri i 5 kolumner - CENTRERAD TABELL
            if !self.entries.is_empty() {
                ui.add_space(20.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("🖼️ BILDGALLERI").size(24.0).strong()
                        .color(egui::Color32::from_rgb(100, 200, 255)));
                    ui.label(RichText::new(format!("📊 {} bilder", self.entries.len()))
                        .size(14.0).color(egui::Color32::from_rgb(200, 200, 255)));
                });
                ui.add_space(20.0);
                
                // Centrerad scroll area
                ScrollArea::vertical()
                    .max_height(ui.available_height() - 80.0)
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            let entries_with_data: Vec<_> = self.entries.iter()
                                .filter(|e| e.base64.is_some())
                                .collect();
                            
                            // Tabell med 5 kolumner - centrerad
                            let columns = 5;
                            let thumbnail_size = 200.0;
                            let spacing = 15.0;
                            
                            // Snygg tabell-ram
                            egui::Frame::none()
                                .fill(egui::Color32::from_rgb(25, 25, 35))
                                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(60, 60, 80)))
                                .rounding(8.0)
                                .inner_margin(20.0)
                                .show(ui, |ui| {
                                    egui::Grid::new("gallery_table")
                                        .spacing([spacing, spacing])
                                        .show(ui, |ui| {
                                            for (idx, entry) in entries_with_data.iter().enumerate() {
                                                if let Some(b64) = &entry.base64 {
                                                    if let Ok(decoded) = general_purpose::STANDARD.decode(b64) {
                                                        if let Ok(img) = image::load_from_memory(&decoded) {
                                                            let rgba = img.to_rgba8();
                                                            let size = [rgba.width() as usize, rgba.height() as usize];
                                                            let pixels = rgba.as_flat_samples();
                                                            let color_image = egui::ColorImage::from_rgba_unmultiplied(size, pixels.as_slice());
                                                            
                                                            let texture = self.texture_cache.entry(entry.namn.clone())
                                                                .or_insert_with(|| ctx.load_texture(&entry.namn, color_image, Default::default()));
                                                            
                                                            // Bildcell med ram
                                                            egui::Frame::none()
                                                                .fill(egui::Color32::from_rgb(35, 35, 50))
                                                                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(70, 70, 90)))
                                                                .rounding(6.0)
                                                                .inner_margin(10.0)
                                                                .show(ui, |ui| {
                                                                    ui.vertical_centered(|ui| {
                                                                        let img_width = img.width() as f32;
                                                                        let img_height = img.height() as f32;
                                                                        let aspect = img_width / img_height;
                                                                        
                                                                        let display_size = if aspect > 1.0 {
                                                                            egui::vec2(thumbnail_size, thumbnail_size / aspect)
                                                                        } else {
                                                                            egui::vec2(thumbnail_size * aspect, thumbnail_size)
                                                                        };
                                                                        
                                                                        // Hover-effekt: dubbelt så stor
                                                                        let image_response = ui.add(egui::Image::new((texture.id(), display_size)));
                                                                        image_response.on_hover_ui(|ui| {
                                                                            let hover_size = display_size * 2.0;
                                                                            ui.add(egui::Image::new((texture.id(), hover_size)));
                                                                        });
                                                                        
                                                                        ui.add_space(5.0);
                                                                        ui.label(RichText::new(&entry.namn)
                                                                            .size(11.0)
                                                                            .color(egui::Color32::from_rgb(180, 180, 200)));
                                                                    });
                                                                });
                                                            
                                                            // Ny rad efter varje 5:e bild
                                                            if (idx + 1) % columns == 0 {
                                                                ui.end_row();
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        });
                                });
                        });
                    });
            }
        });
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // FUNKTION 5: RADERA ID-KOD
    // ═══════════════════════════════════════════════════════════════════════════
    
    fn show_delete_id(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(30.0);
            ui.label(RichText::new("🗑️ Radera ID-kod").size(26.0).strong()
                .color(egui::Color32::from_rgb(255, 100, 100)));
            ui.add_space(30.0);
            
            // Snygg centrerad tabell
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(35, 25, 25))
                .stroke(egui::Stroke::new(2.0, egui::Color32::from_rgb(80, 60, 60)))
                .rounding(10.0)
                .inner_margin(30.0)
                .show(ui, |ui| {
                    ui.set_max_width(500.0);
                    
                    ui.label(RichText::new("⚠️ VARNING: Detta raderar ALLA bilder med detta ID!")
                        .size(13.0).color(egui::Color32::from_rgb(255, 200, 100)));
                    ui.add_space(15.0);
                    
                    ui.label(RichText::new("ID-kod att radera:").size(14.0).strong());
                    ui.add_space(5.0);
                    ui.add_sized([450.0, 30.0], egui::TextEdit::singleline(&mut self.identifier_input));
                    ui.add_space(15.0);
                    
                    ui.label(RichText::new("Lösenord för verifiering:").size(14.0).strong());
                    ui.add_space(5.0);
                    ui.add_sized([450.0, 30.0], egui::TextEdit::singleline(&mut self.password_input).password(true));
                    ui.add_space(25.0);
                    ui.separator();
                    ui.add_space(15.0);
                    
                    ui.horizontal(|ui| {
                        if ui.add_sized([130.0, 40.0], egui::Button::new("⬅️ Tillbaka")).clicked() {
                            self.mode = AppMode::Welcome;
                        }
                        ui.add_space(20.0);
                        if ui.add_sized([250.0, 40.0], egui::Button::new("🗑️ Radera PERMANENT")).clicked() {
                            if !self.identifier_input.is_empty() && !self.password_input.is_empty() {
                                // Verifiera lösenord först
                                match decrypt_file(&self.identifier_input, &self.password_input) {
                                    Ok(_) => {
                                        // Lösenord korrekt, radera ID
                                        match delete_id(&self.identifier_input) {
                                            Ok(_) => {
                                                self.message = format!("✅ ID '{}' har raderats", self.identifier_input);
                                                self.identifier_input.clear();
                                                self.password_input.clear();
                                            }
                                            Err(e) => {
                                                self.message = format!("❌ {}", e);
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        self.message = "❌ Fel lösenord eller ID finns inte".to_string();
                                    }
                                }
                            } else {
                                self.message = "❌ Fyll i ID och lösenord".to_string();
                            }
                        }
                    });
                    
                    if !self.message.is_empty() {
                        ui.add_space(20.0);
                        ui.label(RichText::new(&self.message).size(13.0));
                    }
                });
        });
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // FUNKTION 6: KONTROLLERA AI
    // ═══════════════════════════════════════════════════════════════════════════
    
    fn show_check_ai(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(30.0);
            ui.label(RichText::new("🤖 Kontrollera AI").size(26.0).strong()
                .color(egui::Color32::from_rgb(150, 100, 255)));
            ui.add_space(30.0);
            
            // Snygg centrerad tabell
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(25, 25, 35))
                .stroke(egui::Stroke::new(2.0, egui::Color32::from_rgb(60, 60, 80)))
                .rounding(10.0)
                .inner_margin(30.0)
                .show(ui, |ui| {
                    ui.set_max_width(500.0);
                    
                    ui.label(RichText::new("Mapp att skanna:").size(14.0).strong());
                    ui.add_space(5.0);
                    ui.add_sized([450.0, 30.0], egui::TextEdit::singleline(&mut self.folder_path_input));
                    ui.add_space(10.0);
                    
                    if ui.add_sized([200.0, 35.0], egui::Button::new("📂 Välj mapp")).clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_folder() {
                            self.folder_path_input = path.to_string_lossy().to_string();
                        }
                    }
                    
                    ui.add_space(25.0);
                    ui.separator();
                    ui.add_space(15.0);
                    
                    ui.horizontal(|ui| {
                        if ui.add_sized([130.0, 40.0], egui::Button::new("⬅️ Tillbaka")).clicked() {
                            self.mode = AppMode::Welcome;
                        }
                        ui.add_space(20.0);
                        if ui.add_sized([250.0, 40.0], egui::Button::new("🔍 Skanna för AI-filer")).clicked() {
                    if !self.folder_path_input.is_empty() {
                        let detector = detector::Detector::new();
                        let mut ai_files = Vec::new();
                        
                        if let Ok(entries) = fs::read_dir(&self.folder_path_input) {
                            for entry in entries.flatten() {
                                if let Ok(path) = entry.path().canonicalize() {
                                    if let Ok(result) = detector.scan_path(&path) {
                                        // Kolla ai_likely fältet istället för kind
                                        if result.ai_likely {
                                            let reasons_str = result.reasons.join(", ");
                                            ai_files.push(format!("🚨 {} [{}]\n   → {}", 
                                                result.path.display(), 
                                                result.kind.to_uppercase(), 
                                                reasons_str));
                                        }
                                    }
                                }
                            }
                        }
                        
                        self.ai_scan_results = ai_files;
                        if self.ai_scan_results.is_empty() {
                            self.message = "✅ Inga AI-genererade filer hittades".to_string();
                        } else {
                            self.message = format!("🚨 Hittade {} AI-genererade filer (bilder/videor)", self.ai_scan_results.len());
                        }
                    } else {
                        self.message = "❌ Välj en mapp".to_string();
                    }
                        }
                    });
                    
                    if !self.message.is_empty() {
                        ui.add_space(20.0);
                        ui.label(RichText::new(&self.message).size(13.0));
                    }
                });
            
            // Visa resultat utanför tabellen
            if !self.ai_scan_results.is_empty() {
                ui.add_space(20.0);
                ui.label(RichText::new("🚨 AI-Genererade Filer Hittade:").size(18.0).strong()
                    .color(egui::Color32::from_rgb(255, 100, 100)));
                ui.add_space(10.0);
                
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(35, 25, 35))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(70, 60, 70)))
                    .rounding(8.0)
                    .inner_margin(15.0)
                    .show(ui, |ui| {
                        ScrollArea::vertical().max_height(500.0).show(ui, |ui| {
                            for result in &self.ai_scan_results {
                                ui.label(RichText::new(result).size(13.0).color(egui::Color32::from_rgb(255, 180, 180)));
                                ui.add_space(10.0);
                            }
                        });
                    });
            }
        });
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // FUNKTION 7: DESIGNA DATABASEN
    // ═══════════════════════════════════════════════════════════════════════════
    
    fn show_design(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.label(RichText::new("🎨 Designa databasen").size(26.0).strong()
                .color(egui::Color32::from_rgb(255, 150, 100)));
            ui.add_space(15.0);
            
            // Snygg centrerad tabell
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(25, 25, 35))
                .stroke(egui::Stroke::new(2.0, egui::Color32::from_rgb(60, 60, 80)))
                .rounding(10.0)
                .inner_margin(30.0)
                .show(ui, |ui| {
                    ui.set_max_width(800.0);
                    
                    // Tema-namn
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("📝 Tema-namn:").size(14.0).strong());
                        ui.add_space(5.0);
                        if ui.add_sized([200.0, 25.0], egui::TextEdit::singleline(&mut self.theme_config.name)).changed() {
                            self.design_modified = true;
                        }
                    });
                    
                    ui.add_space(20.0);
                    ui.separator();
                    ui.add_space(15.0);
                    
                    // Färginställningar med scrollbar
                    ui.label(RichText::new("🎨 Färger").size(16.0).strong());
                    ui.add_space(10.0);
                    
                    ScrollArea::vertical().max_height(400.0).show(ui, |ui| {
                        egui::Grid::new("color_grid")
                            .num_columns(3)
                            .spacing([15.0, 10.0])
                            .striped(true)
                            .show(ui, |ui| {
                                // Primärfärg
                                ui.label(RichText::new("Primärfärg:").size(13.0));
                                let mut primary_color = desig::parse_hex_color(&self.theme_config.primary_color)
                                    .unwrap_or(egui::Color32::from_rgb(74, 144, 226));
                                if ui.color_edit_button_srgba(&mut primary_color).changed() {
                                    self.theme_config.primary_color = desig::color_to_hex(primary_color);
                                    self.design_modified = true;
                                }
                                ui.label(&self.theme_config.primary_color);
                                ui.end_row();
                                
                                // Sekundärfärg
                                ui.label(RichText::new("Sekundärfärg:").size(13.0));
                                let mut secondary_color = desig::parse_hex_color(&self.theme_config.secondary_color)
                                    .unwrap_or(egui::Color32::from_rgb(126, 211, 33));
                                if ui.color_edit_button_srgba(&mut secondary_color).changed() {
                                    self.theme_config.secondary_color = desig::color_to_hex(secondary_color);
                                    self.design_modified = true;
                                }
                                ui.label(&self.theme_config.secondary_color);
                                ui.end_row();
                                
                                // Bakgrundsfärg
                                ui.label(RichText::new("Bakgrund:").size(13.0));
                                let mut bg_color = desig::parse_hex_color(&self.theme_config.background_color)
                                    .unwrap_or(egui::Color32::from_rgb(30, 30, 46));
                                if ui.color_edit_button_srgba(&mut bg_color).changed() {
                                    self.theme_config.background_color = desig::color_to_hex(bg_color);
                                    self.design_modified = true;
                                }
                                ui.label(&self.theme_config.background_color);
                                ui.end_row();
                                
                                // Textfärg
                                ui.label(RichText::new("Textfärg:").size(13.0));
                                let mut text_color = desig::parse_hex_color(&self.theme_config.text_color)
                                    .unwrap_or(egui::Color32::WHITE);
                                if ui.color_edit_button_srgba(&mut text_color).changed() {
                                    self.theme_config.text_color = desig::color_to_hex(text_color);
                                    self.design_modified = true;
                                }
                                ui.label(&self.theme_config.text_color);
                                ui.end_row();
                                
                                // Knappfärg
                                ui.label(RichText::new("Knappfärg:").size(13.0));
                                let mut button_color = desig::parse_hex_color(&self.theme_config.button_color)
                                    .unwrap_or(egui::Color32::from_rgb(60, 60, 80));
                                if ui.color_edit_button_srgba(&mut button_color).changed() {
                                    self.theme_config.button_color = desig::color_to_hex(button_color);
                                    self.design_modified = true;
                                }
                                ui.label(&self.theme_config.button_color);
                                ui.end_row();
                                
                                // Knapp hover
                                ui.label(RichText::new("Knapp (hover):").size(13.0));
                                let mut button_hover = desig::parse_hex_color(&self.theme_config.button_hover_color)
                                    .unwrap_or(egui::Color32::from_rgb(74, 74, 96));
                                if ui.color_edit_button_srgba(&mut button_hover).changed() {
                                    self.theme_config.button_hover_color = desig::color_to_hex(button_hover);
                                    self.design_modified = true;
                                }
                                ui.label(&self.theme_config.button_hover_color);
                                ui.end_row();
                                
                                // Accentfärg
                                ui.label(RichText::new("Accentfärg:").size(13.0));
                                let mut accent_color = desig::parse_hex_color(&self.theme_config.accent_color)
                                    .unwrap_or(egui::Color32::from_rgb(100, 200, 255));
                                if ui.color_edit_button_srgba(&mut accent_color).changed() {
                                    self.theme_config.accent_color = desig::color_to_hex(accent_color);
                                    self.design_modified = true;
                                }
                                ui.label(&self.theme_config.accent_color);
                                ui.end_row();
                                
                                // Felfärg
                                ui.label(RichText::new("Felfärg:").size(13.0));
                                let mut error_color = desig::parse_hex_color(&self.theme_config.error_color)
                                    .unwrap_or(egui::Color32::from_rgb(255, 107, 107));
                                if ui.color_edit_button_srgba(&mut error_color).changed() {
                                    self.theme_config.error_color = desig::color_to_hex(error_color);
                                    self.design_modified = true;
                                }
                                ui.label(&self.theme_config.error_color);
                                ui.end_row();
                                
                                // Framgångsfärg
                                ui.label(RichText::new("Framgång:").size(13.0));
                                let mut success_color = desig::parse_hex_color(&self.theme_config.success_color)
                                    .unwrap_or(egui::Color32::from_rgb(81, 207, 102));
                                if ui.color_edit_button_srgba(&mut success_color).changed() {
                                    self.theme_config.success_color = desig::color_to_hex(success_color);
                                    self.design_modified = true;
                                }
                                ui.label(&self.theme_config.success_color);
                                ui.end_row();
                            });
                    });
                    
                    ui.add_space(15.0);
                    ui.separator();
                    ui.add_space(15.0);
                    
                    // Layoutinställningar
                    ui.label(RichText::new("📐 Layout").size(16.0).strong());
                    ui.add_space(10.0);
                    
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Rundning:").size(13.0));
                        ui.add_space(10.0);
                        if ui.add(egui::Slider::new(&mut self.theme_config.border_radius, 0.0..=20.0)
                            .text("px")).changed() {
                            self.design_modified = true;
                        }
                    });
                    
                    ui.add_space(5.0);
                    
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Mellanrum:").size(13.0));
                        ui.add_space(10.0);
                        if ui.add(egui::Slider::new(&mut self.theme_config.spacing, 5.0..=30.0)
                            .text("px")).changed() {
                            self.design_modified = true;
                        }
                    });
                    
                    ui.add_space(5.0);
                    
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Ramtjocklek:").size(13.0));
                        ui.add_space(10.0);
                        if ui.add(egui::Slider::new(&mut self.theme_config.panel_stroke_width, 0.0..=5.0)
                            .text("px")).changed() {
                            self.design_modified = true;
                        }
                    });
                    
                    ui.add_space(5.0);
                    
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Fontstorlek:").size(13.0));
                        ui.add_space(10.0);
                        if ui.add(egui::Slider::new(&mut self.theme_config.font_size, 10.0..=24.0)
                            .text("pt")).changed() {
                            self.design_modified = true;
                        }
                    });
                    
                    ui.add_space(25.0);
                    ui.separator();
                    ui.add_space(15.0);
                    
                    // Knappar
                    ui.horizontal(|ui| {
                        if ui.add_sized([130.0, 40.0], egui::Button::new("⬅️ Tillbaka")).clicked() {
                            self.mode = AppMode::Welcome;
                            self.design_modified = false;
                        }
                        ui.add_space(10.0);
                        
                        if ui.add_sized([180.0, 40.0], egui::Button::new("🔄 Återställ")).clicked() {
                            self.theme_config = desig::get_default_theme();
                            self.design_modified = true;
                            self.message = "✅ Återställt till standardtema".to_string();
                        }
                        ui.add_space(10.0);
                        
                        let save_button = egui::Button::new(RichText::new("💾 Spara & Applicera")
                            .color(if self.design_modified { 
                                egui::Color32::from_rgb(100, 255, 100) 
                            } else { 
                                egui::Color32::GRAY 
                            }));
                        
                        if ui.add_sized([200.0, 40.0], save_button).clicked() {
                            match desig::save_theme_config(&self.theme_config) {
                                Ok(_) => {
                                    self.message = "✅ Tema sparat! Starta om för att se alla ändringar.".to_string();
                                    self.design_modified = false;
                                }
                                Err(e) => {
                                    self.message = format!("❌ Kunde inte spara: {}", e);
                                }
                            }
                        }
                    });
                    
                    if !self.message.is_empty() {
                        ui.add_space(15.0);
                        ui.label(RichText::new(&self.message).size(14.0)
                            .color(if self.message.starts_with("✅") {
                                egui::Color32::from_rgb(100, 255, 100)
                            } else {
                                egui::Color32::from_rgb(255, 100, 100)
                            }));
                    }
                    
                    if self.design_modified {
                        ui.add_space(10.0);
                        ui.label(RichText::new("⚠️ Du har osparade ändringar!")
                            .size(13.0)
                            .color(egui::Color32::from_rgb(255, 200, 100)));
                    }
                });
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN - STARTA APPLIKATIONEN
// ═══════════════════════════════════════════════════════════════════════════════

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_title("AI Databasen"),
        ..Default::default()
    };
    
    eframe::run_native(
        "AI Databasen",
        options,
        Box::new(|cc| {
            setup_fonts(&cc.egui_ctx);
            Ok(Box::<MyApp>::default())
        }),
    )
}

