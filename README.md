# TigerPass - An Open-Source, Secure Password Manager

A modern, open-source, secure password management application built with Python, featuring encryption, two-factor authentication, and a user-friendly GUI interface.

# Images
![image](https://github.com/user-attachments/assets/e443ec33-4fbf-46e9-8bb6-3b530f22cd15)
![image](https://github.com/user-attachments/assets/b591a93e-b338-48fb-9d37-e19502074a9e)
![image](https://github.com/user-attachments/assets/b83748a4-576b-40d2-9dd0-7ed48a23bfd3)
![image](https://github.com/user-attachments/assets/8a038d92-67bc-44ad-8508-79a4a9129a37)


## Features

- 🔐 Strong AES encryption for password storage
- 🔑 Master password protection
- 📱 Two-factor authentication (2FA) support
- 🎨 Modern, intuitive graphical user interface
- 🌗 Dark theme interface
- 🎲 Secure password generator
- 📋 Easy password management (add, view, edit, delete)
- 💾 Encrypted local storage

## Requirements

- Python 3.x
- See `requirements.txt` for Python package dependencies

## Installation

1. Clone the repository
```bash
git clone https://github.com/jviars/tigerpass.git
cd tigerpass
```

2. Install required packages
```bash
pip install -r requirements.txt
```

3. Run the application
```bash
python main.py
```

## Usage

1. **First Time Setup**
   - Enter your email address
   - Create a strong master password
   - Set up 2FA using your preferred authenticator app

2. **Managing Passwords**
   - Add new password entries
   - View stored passwords
   - Generate secure passwords
   - Edit existing entries
   - Delete unused entries

## Security Features

- AES encryption for all stored passwords
- PBKDF2 key derivation for master password
- Two-factor authentication
- Secure random password generation
- Encrypted local storage

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built using PyQt6 for the modern GUI interface
- Uses `pycryptodome` for encryption
- Implements `pyotp` for 2FA functionality

## Disclaimer

This password manager is provided as-is, without any warranties. Users should always exercise caution when storing sensitive information.

---
Made with ❤️ by jviars
