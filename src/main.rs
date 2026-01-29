use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use clap::Parser;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const PBKDF2_ITER: u32 = 1_000_000;
const KEY_LEN: usize = 32;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Relative path to the password file
    #[arg(short, long)]
    password_file: String,
    /// Relative path filename to the input file
    #[arg(short, long)]
    input: String,
    /// Relative path filename to the output file (if this field is empty, the output will be overwritten input file)
    #[arg(short, long)]
    output: Option<String>,
    /// decryption operation
    #[arg(short, long, default_value_t = false)]
    decrypt: bool,
    /// encryption operation
    #[arg(short, long, default_value_t = false)]
    encrypt: bool,
}

fn main() {
    let args = Args::parse();

    if args.password_file.is_empty() {
        eprintln!("Password file path is required.");
        std::process::exit(1);
    }

    if args.decrypt == args.encrypt || (!args.decrypt && !args.encrypt) {
        eprintln!("Specify either --encrypt or --decrypt.");
        std::process::exit(1);
    }

    let password = fs::read_to_string(&args.password_file)
        .expect("Failed to read password file")
        .trim()
        .to_owned();
    if password.is_empty() {
        eprintln!("Password file cannot be empty.");
        std::process::exit(1);
    }

    match args.encrypt {
        true => {
            let input_path = Path::new(&args.input);
            let mut file = File::open(input_path).expect("Failed to open input file");
            let mut file_data = Vec::new();
            file.read_to_end(&mut file_data)
                .expect("Failed to read file");

            let filename = input_path.file_name().unwrap().to_str().unwrap();
            let (enc_filename, salt1, nonce1) =
                encrypt_with_password(filename.as_bytes(), &password);

            let (enc_data, salt2, nonce2) = encrypt_with_password(&file_data, &password);

            let out_path = match &args.output {
                Some(path) if !path.is_empty() => Path::new(path).to_path_buf(),
                _ => input_path.to_path_buf(),
            };
            let mut out_file = File::create(&out_path).expect("Failed to create output file");

            out_file.write_all(&salt1).unwrap();
            out_file.write_all(&nonce1).unwrap();
            out_file
                .write_all(&(enc_filename.len() as u32).to_le_bytes())
                .unwrap();
            out_file.write_all(&enc_filename).unwrap();
            out_file.write_all(&salt2).unwrap();
            out_file.write_all(&nonce2).unwrap();
            out_file
                .write_all(&(enc_data.len() as u64).to_le_bytes())
                .unwrap();
            out_file.write_all(&enc_data).unwrap();
            out_file.sync_all().unwrap();

            println!("Encrypted file written to: {}", out_path.display());
        }
        false => {
            let input_path = Path::new(&args.input);
            let mut file = File::open(input_path).expect("Failed to open encrypted file");
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)
                .expect("Failed to read encrypted file");

            let (_, data) = decrypt_file(&buf, &password).expect("Decryption failed");

            let out_path = match &args.output {
                Some(path) if !path.is_empty() => Path::new(path).to_path_buf(),
                _ => input_path.to_path_buf(),
            };
            let mut out_file = File::create(&out_path).expect("Failed to create output file");
            out_file
                .write_all(&data)
                .expect("Failed to write decrypted data");
            out_file.sync_all().unwrap();
            println!("Decrypted file written to: {}", out_path.display());
        }
    }
}
fn decrypt_file(buf: &[u8], password: &str) -> Result<(String, Vec<u8>), String> {
    let mut offset = 0;
    if buf.len() < offset + SALT_LEN {
        return Err("Invalid file: missing salt1".to_string());
    }
    let salt1 = &buf[offset..offset + SALT_LEN];
    offset += SALT_LEN;

    if buf.len() < offset + NONCE_LEN {
        return Err("Invalid file: missing nonce1".to_string());
    }
    let nonce1 = &buf[offset..offset + NONCE_LEN];
    offset += NONCE_LEN;

    if buf.len() < offset + 4 {
        return Err("Invalid file: missing filename length".to_string());
    }
    let len_bytes = &buf[offset..offset + 4];
    let enc_filename_len =
        u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    offset += 4;

    if buf.len() < offset + enc_filename_len {
        return Err("Invalid file: missing encrypted filename".to_string());
    }
    let enc_filename = &buf[offset..offset + enc_filename_len];
    offset += enc_filename_len;

    if buf.len() < offset + SALT_LEN {
        return Err("Invalid file: missing salt2".to_string());
    }
    let salt2 = &buf[offset..offset + SALT_LEN];
    offset += SALT_LEN;

    if buf.len() < offset + NONCE_LEN {
        return Err("Invalid file: missing nonce2".to_string());
    }
    let nonce2 = &buf[offset..offset + NONCE_LEN];
    offset += NONCE_LEN;

    if buf.len() < offset + 8 {
        return Err("Invalid file: missing data length".to_string());
    }
    let len_bytes = &buf[offset..offset + 8];
    let enc_data_len = u64::from_le_bytes([
        len_bytes[0],
        len_bytes[1],
        len_bytes[2],
        len_bytes[3],
        len_bytes[4],
        len_bytes[5],
        len_bytes[6],
        len_bytes[7],
    ]) as usize;
    offset += 8;

    if buf.len() < offset + enc_data_len {
        return Err("Invalid file: missing encrypted data".to_string());
    }
    let enc_data = &buf[offset..offset + enc_data_len];
    let mut key1 = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt1, PBKDF2_ITER, &mut key1);
    let cipher1 = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key1));
    let filename_bytes = cipher1
        .decrypt(Nonce::from_slice(nonce1), enc_filename)
        .map_err(|_| "Failed to decrypt filename".to_string())?;
    let filename =
        String::from_utf8(filename_bytes).map_err(|_| "Filename is not valid UTF-8".to_string())?;
    let mut key2 = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt2, PBKDF2_ITER, &mut key2);
    let cipher2 = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key2));
    let data = cipher2
        .decrypt(Nonce::from_slice(nonce2), enc_data)
        .map_err(|_| "Failed to decrypt data".to_string())?;
    Ok((filename, data))
}

fn encrypt_with_password(
    data: &[u8],
    password: &str,
) -> (Vec<u8>, [u8; SALT_LEN], [u8; NONCE_LEN]) {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, PBKDF2_ITER, &mut key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), data)
        .expect("encryption failure!");
    (ciphertext, salt, nonce)
}
