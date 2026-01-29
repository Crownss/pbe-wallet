# pbe-wallet

A simple Rust CLI tool for password-based encryption (PBE) of files and filenames.

## Features

- Encrypts and decrypts files using a password from a file
- Encrypts the filename as well as the file contents
- Uses AES-256-GCM and PBKDF2 for strong encryption
- Command-line interface with `clap`

## Usage (recommend to build first)

Build:

```
cargo b --release
```
Run:

```
./pbe-wallet
```
- `-e` : Encrypt mode
- `-d` : Decrypt mode
- `-i` : Input relative file path
- `-p` : Password relative file path
- `-o` : Output relative file path (optional, default is current input file was supplied with `-i`)

Example (encrypt):<br/><br/>
this is just an example it doesn't care file format you'll be use, all you'll need just `-p` param for load file password<br/>
in other words you can encrypt your file using `LICENSE` or even `main.rs` in order to encrypt another file
```
./pbe-wallet -p ./password.txt -i ./secret.txt -e
./pbe-wallet -p ./LICENSE -i ./Cargo.toml -e
```
Example (decrypt):
```
./pbe-wallet -p ./password.txt -i ./secret.txt -d
./pbe-wallet -p ./LICENSE -i ./Cargo.toml -d
```

## Notes

if file is encrypted you can encrypt it many times for more secure but absolutely that mean also need decrypt many times

keep this in your mind "doesn't care how N times you encrypt but you'll also need N times to decrypt it back"

you'll be need bash execution file if you want to use for folder like `my-secret-folder/*`

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.