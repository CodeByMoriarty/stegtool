# File Analysis Tool - Advanced Steganography & Hidden Data Detection

This powerful open-source tool is designed for advanced steganography and hidden data detection. It can scan and analyze various file formats (images, PDFs, DOCX, ZIP archives, audio, etc.) to identify and extract hidden messages, detect anomalies, analyze file signatures, entropy, and much more.

## Features

### 1. **Steganography Detection**
   - **LSB Analysis**: Detect hidden messages using Least Significant Bit (LSB) steganography in images.
   - **Metadata Extraction**: Extract hidden messages or flags from image metadata (EXIF).
   - **Steganographic Algorithms**: Support for multiple steganographic techniques for hidden data in images and audio files.

### 2. **Advanced File Analysis**
   - **Strings Extraction**: Extract and search for readable strings (text) from binary files.
   - **File Signature Checking**: Automatically identify the file type using magic bytes (e.g., JPEG, PNG, PDF).
   - **Entropy Analysis**: Calculate file entropy to detect compression, encryption, or hidden data.
   - **Binwalk-like Analysis**: Detect embedded files or hidden data in binary files.
   - **Hashing (MD5, SHA256)**: Calculate hashes of files for integrity checks or to compare files.

### 3. **Text Extraction and Search**
   - **PDF Text Extraction**: Extract text from PDFs and search for keywords or hidden messages.
   - **Word Document Text Extraction**: Extract and analyze text from DOCX files for hidden content.
   - **ZIP Archive Extraction**: Extract files from ZIP archives and search for hidden messages inside.
   - **Audio File Analysis**: Analyze MP3 and WAV files for hidden data or anomalies.

### 4. **Interactive GUI**
   - User-friendly GUI for selecting files, specifying search keywords, and displaying analysis results.
   - Supports drag-and-drop file analysis for quick scanning.

### 5. **Advanced Data Forensics**
   - **File Carving**: Automatically carve out fragments of hidden data embedded within files.
   - **Compression/Encryption Detection**: Detect files that appear compressed or encrypted based on entropy analysis.
   - **Steganalysis of Audio**: Detect hidden data or messages within audio files, focusing on steganography in WAV and MP3 formats.
   - **PDF and DOCX Metadata Inspection**: Look into embedded objects or hidden fields inside documents.

## Installation

### Prerequisites

1. **Python 3.x** (recommended version 3.8 or higher)
2. **Git** (for cloning the repository)

### Steps

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/file-analysis-tool.git
   cd file-analysis-tool
