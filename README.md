# ShadowCrypt

**ShadowCrypt** is an open-source cryptography tool designed for secure text encryption, decryption, and translation into Morse and binary codes. Built with PySide6 and licensed under the BSD 3-Clause Clear License, ShadowCrypt offers a user-friendly interface for developers, security enthusiasts, and anyone interested in protecting their communications.

📅 **Launch Date**: May 11, 2025, 1:00 PM IST\
🔗 **GitHub**: [https://github.com/VeduStorm/shadow-crypt](https://github.com/VeduStorm/shadow-crypt)\
📋 **Survey**: [Feedback Form](https://forms.gle/7G5yDveKVuDGUo377)\
📧 **Contact**: vedant.storm@gmail.com

---

## Features

- **Text Encryption/Decryption**: Securely encrypt and decrypt text using Fernet with 8-digit numeric keys.
- **Morse & Binary Translation**: Convert text to/from Morse and binary code in Authentic (standard) or Secret (custom) modes.
- **User Authentication**: SHA-256 hashed passwords with support for up to two users.
- **Modern GUI**: Intuitive interface with tabs for cryptography and dictionary operations.
- **Cross-Platform**: Optimised for macOS Silicon, with planned support for Windows and Linux.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/VeduStorm/shadow-crypt.git
   cd shadow-crypt
   ```
2. Install dependencies:

   ```bash
   pip install PyQt5 PySide6 cryptography python-dotenv hkdf smtplib 
   ```
3. Run the application:

   ```bash
   python main.py
   ```

## Usage

1. **First-Time Setup**: Create a user account with a username and password.
2. **Cryptography Tab**:
   - Enter text in the input field.
   - Generate or input an 8-digit key.
   - Click "Encrypt" or "Decrypt" to process the text.
3. **Dictionary Tab**:
   - Select Authentic or Secret mode.
   - Input text and choose "Encrypt" or "Decrypt" to translate to/from Morse or binary.
4. **Feedback**: After 2–5 days, complete the Survey Form to share your experience.

## Development Roadmap

- **v1.0.beta1** (May 11, 2025, 1:00 PM IST): Initial release with PyQt5, file-based encryption, and basic authentication.
- **v1.0.2** (May 15, 2025, 12:00 PM IST): PySide6 migration, simplified key generation, and stability improvements.
- **v2.0.alpha1** (May 17, 2025, 12:00 PM IST): Enhanced GUI, OTP password recovery, and HKDF key derivation.

**Future Plans**:

- Optimize GUI for accessibility and aesthetics.
- Support Windows and Linux platforms.
- Add advanced encryption algorithms and multi-user support.

## Contribute

We’re excited to build ShadowCrypt with the community! Here’s how you can help:

- **Fork & Test**: Clone the repo, test the app, and submit pull requests with improvements.
- **Feature Suggestions**: Propose at least three features, such as:
  - AES-256 encryption support.
  - Real-time key sharing for collaboration.
  - Message export/import functionality.
- **Bug Reports**: Report at least five bugs, focusing on:
  - GUI responsiveness across resolutions.
  - Morse/binary translation edge cases.
  - Key generation consistency.
  - Authentication errors.
  - File handling in packaged builds.
- **Submit Feedback**: Email suggestions or bugs to vedant.storm@gmail.com or contact us via Vedant Gandhi’s GitHub.

Exceptional contributions will be recognized in the **Acknowledgements** section!

## Credits

- **Developed by**: [Vedant Gandhi](https://github.com/vedustorm) & [Khush Shah](https://github.com/kspro416)
- **License**: BSD 3-Clause Clear License

## Acknowledgements

Stay tuned for contributors who help shape ShadowCrypt with their feedback and code!

## Support

Encounter issues? Open an issue on GitHub or email vedant.storm@gmail.com.

Join us in making secure communication accessible to all with ShadowCrypt!
