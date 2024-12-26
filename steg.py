import os
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
from stegano import lsb
import exiftool
import PyPDF2
import docx
import zipfile
import hashlib
import numpy as np
import binascii
import wave
import audioop


# Function to extract printable strings from a file (similar to the "strings" command)
def extract_strings(file_path, min_length=4):
    result = ""
    try:
        with open(file_path, "rb") as f:
            content = f.read()
            # Extract sequences of printable characters with a minimum length
            strings = []
            temp = ""
            for byte in content:
                if 32 <= byte <= 126:  # Check if byte is a printable character
                    temp += chr(byte)
                else:
                    if len(temp) >= min_length:
                        strings.append(temp)
                    temp = ""
            # Add last string if it's valid
            if len(temp) >= min_length:
                strings.append(temp)

            if strings:
                result += "[*] Extracted strings:\n"
                for s in strings:
                    result += s + "\n"
            else:
                result += "[*] No printable strings found.\n"
    except Exception as e:
        result = f"[!] Error extracting strings: {e}\n"
    return result


# Function to analyze file signature (magic bytes)
def check_file_signature(file_path):
    result = ""
    try:
        with open(file_path, "rb") as f:
            magic_bytes = f.read(4)
            result += f"File signature (magic bytes): {binascii.hexlify(magic_bytes)}\n"
            if magic_bytes.startswith(b"\xFF\xD8"):  # JPEG magic bytes
                result += "[*] This is likely a JPEG file.\n"
            elif magic_bytes.startswith(b"\x89\x50\x4E\x47"):  # PNG magic bytes
                result += "[*] This is likely a PNG file.\n"
            elif magic_bytes.startswith(b"\x25\x50\x44\x46"):  # PDF magic bytes
                result += "[*] This is likely a PDF file.\n"
            else:
                result += "[*] Unknown file signature.\n"
    except Exception as e:
        result = f"[!] Error checking file signature: {e}\n"
    return result


# Function to analyze entropy (randomness) of the file
def analyze_entropy(file_path):
    result = ""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            entropy = -sum((data.count(byte) / len(data)) * np.log2(data.count(byte) / len(data)) for byte in set(data))
        result = f"Entropy of {file_path}: {entropy}\n"
        if entropy > 7.5:
            result += "[*] High entropy (possible compression or encryption).\n"
        else:
            result += "[*] Low entropy (likely uncompressed text data).\n"
    except Exception as e:
        result = f"[!] Error calculating entropy: {e}\n"
    return result


# Function to analyze and extract hidden files in binary (binwalk-like analysis)
def binwalk_like_analysis(file_path):
    result = ""
    try:
        with open(file_path, "rb") as f:
            content = f.read()
            # Look for typical embedded file signatures
            known_signatures = {
                b"\x7f\x45\x4c\x46": "ELF",  # ELF file signature
                b"\x50\x4b\x03\x04": "ZIP",  # ZIP file signature
                b"\x89\x50\x4e\x47": "PNG",  # PNG file signature
                b"\xff\xd8\xff": "JPEG",  # JPEG file signature
            }
            for sig, file_type in known_signatures.items():
                if sig in content:
                    result += f"[*] Found embedded {file_type} file.\n"
            if not result:
                result = "[*] No embedded files found.\n"
    except Exception as e:
        result = f"[!] Error with binwalk-like analysis: {e}\n"
    return result


# Function to extract text from a PDF file
def extract_pdf_text(file_path, keyword):
    result = ""
    try:
        with open(file_path, "rb") as file:
            reader = PyPDF2.PdfReader(file)
            text = ""
            for page in reader.pages:
                text += page.extract_text()
            
            if keyword in text:
                result += f"Found '{keyword}' in PDF text.\n"
            else:
                result += "[*] Keyword not found in PDF text.\n"
    except Exception as e:
        result = f"[!] Error reading PDF file: {e}\n"
    return result


# Function to extract text from a Word file (DOCX)
def extract_word_text(file_path, keyword):
    result = ""
    try:
        doc = docx.Document(file_path)
        text = ""
        for para in doc.paragraphs:
            text += para.text
        
        if keyword in text:
            result += f"Found '{keyword}' in Word document.\n"
        else:
            result += "[*] Keyword not found in Word document text.\n"
    except Exception as e:
        result = f"[!] Error reading Word file: {e}\n"
    return result


# Function to extract text from a ZIP file
def extract_zip_text(file_path, keyword):
    result = ""
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall('extracted_files')
            extracted_files = os.listdir('extracted_files')
            result += f"Extracted {len(extracted_files)} files from the ZIP archive.\n"
            for extracted_file in extracted_files:
                with open(os.path.join('extracted_files', extracted_file), 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
                    if keyword in text:
                        result += f"Found '{keyword}' in extracted file: {extracted_file}\n"
        return result
    except Exception as e:
        return f"[!] Error with ZIP extraction: {e}\n"


# Function to calculate file hash (MD5, SHA256, etc.)
def hash_file(file_path, algorithm='sha256'):
    result = ""
    try:
        hash_func = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                hash_func.update(chunk)
        result = f"{algorithm.upper()} hash of {file_path}: {hash_func.hexdigest()}\n"
    except Exception as e:
        result = f"[!] Error calculating file hash: {e}\n"
    return result


# Function to analyze audio files (simple check for hidden data)
def analyze_audio(file_path):
    result = ""
    try:
        with wave.open(file_path, 'rb') as audio:
            params = audio.getparams()
            result += f"Audio File Parameters: {params}\n"
            if params.sampwidth == 2:  # Check if it's 16-bit audio, which could hide data
                result += "[*] Audio file could contain hidden data (16-bit audio).\n"
            else:
                result += "[*] No obvious hidden data in audio file.\n"
    except Exception as e:
        result = f"[!] Error analyzing audio file: {e}\n"
    return result


# Function to check file entropy
def analyze_entropy(file_path):
    result = ""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            entropy = -sum((data.count(byte) / len(data)) * np.log2(data.count(byte) / len(data)) for byte in set(data))
        result = f"Entropy of {file_path}: {entropy}\n"
        if entropy > 7.5:
            result += "[*] High entropy (possible compression or encryption).\n"
        else:
            result += "[*] Low entropy (likely uncompressed text data).\n"
    except Exception as e:
        result = f"[!] Error calculating entropy: {e}\n"
    return result


# Main function to run all checks
def run_analysis(file_path, keyword):
    if not os.path.exists(file_path):
        return "[!] The specified file does not exist.\n"

    result = ""
    result += extract_strings(file_path)
    result += check_file_signature(file_path)
    result += binwalk_like_analysis(file_path)
    result += hash_file(file_path, 'sha256')
    result += analyze_entropy(file_path)

    if file_path.lower().endswith(('png', 'jpg', 'jpeg', 'bmp', 'gif')):
        result += extract_lsb(file_path, keyword)
        result += extract_metadata(file_path, keyword)
        result += extract_steganography(file_path, keyword)
    elif file_path.lower().endswith('.pdf'):
        result += extract_pdf_text(file_path, keyword)
    elif file_path.lower().endswith('.docx'):
        result += extract_word_text(file_path, keyword)
    elif file_path.lower().endswith('.zip'):
        result += extract_zip_text(file_path, keyword)
    elif file_path.lower().endswith(('mp3', 'wav')):
        result += analyze_audio(file_path)
    else:
        result += "[*] Unsupported file type for steganography or text extraction.\n"

    return result


# GUI Functionality
def browse_file():
    filename = filedialog.askopenfilename(filetypes=[("All Files", "*.*"),
                                                    ("Image Files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif"),
                                                    ("PDF Files", "*.pdf"),
                                                    ("Word Documents", "*.docx"),
                                                    ("Text Files", "*.txt"),
                                                    ("ZIP Files", "*.zip")])
    
    if filename:
        # Ensure the entry box displays the selected filename
        file_path_entry.delete(0, tk.END)
        file_path_entry.insert(0, filename)


def start_analysis():
    file_path = file_path_entry.get()
    keyword = keyword_entry.get()

    if not file_path or not keyword:
        messagebox.showerror("Error", "Please provide both a file and a keyword.")
        return

    result = run_analysis(file_path, keyword)

    # Display results in the text box
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, result)


# Set up the main window
root = tk.Tk()
root.title("File Analysis Tool")
root.geometry("600x500")

# Create GUI components
file_path_label = tk.Label(root, text="Select File:")
file_path_label.pack(pady=10)

file_path_entry = tk.Entry(root, width=50)
file_path_entry.pack(pady=5)

browse_button = tk.Button(root, text="Browse", command=browse_file)
browse_button.pack(pady=5)

keyword_label = tk.Label(root, text="Keyword to Search For:")
keyword_label.pack(pady=10)

keyword_entry = tk.Entry(root, width=50)
keyword_entry.pack(pady=5)

start_button = tk.Button(root, text="Start Analysis", command=start_analysis)
start_button.pack(pady=20)

result_text = tk.Text(root, width=70, height=15)
result_text.pack(pady=10)

# Start the GUI loop
root.mainloop()
