import os
import hashlib
import binascii
import numpy as np
import re
from PIL import Image
import magic
import pikepdf
import logging
import mimetypes
import base64
from zipfile import ZipFile
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

# Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Helper Function: Calculate File Hash (MD5, SHA256)
def calculate_hash(file_path, hash_type='md5'):
    hash_func = hashlib.md5() if hash_type == 'md5' else hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating hash for {file_path}: {e}")
        return None

# Helper Function: Detect File Type
def detect_file_type(file_path):
    file_type, _ = mimetypes.guess_type(file_path)
    return file_type

# Helper Function: Extract Strings from Files
def extract_strings(file_path, min_length=4):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        strings = re.findall(rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}', data)  # Match printable characters
        return [s.decode('utf-8', errors='ignore') for s in strings]
    except Exception as e:
        logging.error(f"Error extracting strings from {file_path}: {e}")
        return None

# Helper Function: Hex Dump (similar to xxd)
def hex_dump(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        hex_dump = binascii.hexlify(data).decode('utf-8')
        return '\n'.join([hex_dump[i:i+32] for i in range(0, len(hex_dump), 32)])  # Split into lines of 32 characters
    except Exception as e:
        logging.error(f"Error performing hex dump on {file_path}: {e}")
        return None

# Helper Function: Perform Entropy Analysis (Randomness check)
def calculate_entropy(file_path):
    try:
        with open(file_path, 'rb') as f:
            byte_data = f.read()
        entropy = -sum((byte_data.count(i) / len(byte_data)) * np.log2(byte_data.count(i) / len(byte_data)) for i in set(byte_data))
        return entropy
    except Exception as e:
        logging.error(f"Error calculating entropy for {file_path}: {e}")
        return None

# Binwalk-Like File Carving (Detect embedded files in binary)
def binwalk_analysis(file_path):
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
        signature = binascii.hexlify(file_data[:4]).decode('utf-8')
        return signature
    except Exception as e:
        logging.error(f"Error performing binwalk-like analysis on {file_path}: {e}")
        return None

# Extract Text from ZIP Files
def extract_text_from_zip(zip_path):
    try:
        with ZipFile(zip_path, 'r') as zip_file:
            text = ""
            for file in zip_file.namelist():
                with zip_file.open(file) as f:
                    text += f.read().decode('utf-8', errors='ignore')
            return text
    except Exception as e:
        logging.error(f"Error extracting text from ZIP {zip_path}: {e}")
        return None

# Keyword Search Function
def search_keyword_in_text(text, keyword):
    if text and keyword.lower() in text.lower():
        return f"Keyword '{keyword}' found!"
    return f"Keyword '{keyword}' not found."

# Base64 Encoding and Decoding with Padding Fix
def decode_base64(encoded_str):
    try:
        # Ensure proper padding for base64 string
        padded_str = encoded_str + '=' * (-len(encoded_str) % 4)
        decoded_data = base64.b64decode(padded_str).decode('utf-8', errors='ignore')
        return decoded_data
    except Exception as e:
        logging.error(f"Error decoding base64: {e}")
        return None

def encode_base64(data):
    try:
        encoded_data = base64.b64encode(data.encode('utf-8')).decode('utf-8')
        return encoded_data
    except Exception as e:
        logging.error(f"Error encoding to base64: {e}")
        return None

# Extract Image Metadata
def extract_image_metadata(image_path):
    try:
        with Image.open(image_path) as img:
            metadata = img.info  # This could include EXIF data
            return metadata
    except Exception as e:
        logging.error(f"Error extracting metadata from {image_path}: {e}")
        return None

# Extract Text from PDF files
def extract_text_from_pdf(pdf_path):
    try:
        with pikepdf.open(pdf_path) as pdf:
            text = ""
            for page in pdf.pages:
                text += page.extract_text()
            return text
    except Exception as e:
        logging.error(f"Error extracting text from PDF {pdf_path}: {e}")
        return None

# Check for Steganography in Image
def check_for_steganography(image_path):
    try:
        with Image.open(image_path) as img:
            img_data = img.getdata()
            # Basic analysis (you can improve this by looking for LSB encoding or specific patterns)
            if any(px[3] < 255 for px in img_data):  # Check for transparent/odd pixels
                return "Potential steganography detected."
            return "No steganography detected."
    except Exception as e:
        logging.error(f"Error checking for steganography in {image_path}: {e}")
        return None

def extract_and_save_palette(image_path):
    try:
        with Image.open(image_path) as img:
            # Check if the image has a palette (P mode)
            if img.mode == 'P':
                palette = img.getpalette()  # Extract the palette
                palette_filename = f"{os.path.splitext(image_path)[0]}_palette.txt"

                # Save the palette to a text file (RGB triplets)
                with open(palette_filename, 'w') as f:
                    for i in range(0, len(palette), 3):
                        f.write(f"RGB({palette[i]}, {palette[i+1]}, {palette[i+2]})\n")
                
                # Optionally, generate an image showing the palette
                palette_image = Image.new("RGB", (256, 1))  # Generate a simple 1-row image for the palette
                palette_image.putpalette(palette)
                palette_image.save(f"{os.path.splitext(image_path)[0]}_palette.png")
                
                return f"Palette extracted and saved as {palette_filename} and palette image generated as {os.path.splitext(image_path)[0]}_palette.png"
            
            elif img.mode in ['RGB', 'RGBA']:
                # If the image is not in 'P' mode, we can convert it to 'P' mode to extract a palette
                img = img.convert('P')
                palette = img.getpalette()
                palette_filename = f"{os.path.splitext(image_path)[0]}_palette.txt"

                # Save the palette to a text file (RGB triplets)
                with open(palette_filename, 'w') as f:
                    for i in range(0, len(palette), 3):
                        f.write(f"RGB({palette[i]}, {palette[i+1]}, {palette[i+2]})\n")
                
                # Optionally, generate an image showing the palette
                palette_image = Image.new("RGB", (256, 1))  # Generate a simple 1-row image for the palette
                palette_image.putpalette(palette)
                palette_image.save(f"{os.path.splitext(image_path)[0]}_palette.png")
                
                return f"Palette extracted (converted to P mode) and saved as {palette_filename} and palette image generated as {os.path.splitext(image_path)[0]}_palette.png"

            else:
                return "Image mode does not support palette extraction."

    except Exception as e:
        logging.error(f"Error extracting palette from {image_path}: {e}")
        return None


# Main Analysis Function
def analyze_file(file_path, methods, keyword=None):
    results = {}
    
    # Perform Hashing
    if 'hash' in methods:
        results['md5'] = calculate_hash(file_path, 'md5')
        results['sha256'] = calculate_hash(file_path, 'sha256')

    # Perform Strings Extraction
    if 'strings' in methods:
        results['strings'] = extract_strings(file_path)

    # Perform Hex Dump
    if 'hexdump' in methods:
        results['hex_dump'] = hex_dump(file_path)

    # Perform Entropy Analysis
    if 'entropy' in methods:
        results['entropy'] = calculate_entropy(file_path)

    # Perform Binwalk-like Analysis
    if 'binwalk' in methods:
        results['binwalk'] = binwalk_analysis(file_path)

    # Perform ZIP Extraction and Text Search
    if 'extract_zip_text' in methods and detect_file_type(file_path) == 'application/zip':
        zip_text = extract_text_from_zip(file_path)
        results['zip_text'] = zip_text
        if keyword:
            results['zip_keyword_search'] = search_keyword_in_text(zip_text, keyword)

    # Additional methods for base64, PDF text extraction, metadata, and steganography
    if 'base64' in methods:
        base64_data = decode_base64(file_path)
        if base64_data:
            results['base64_decoded'] = base64_data

    if 'metadata' in methods:
        image_metadata = extract_image_metadata(file_path)
        if image_metadata:
            results['image_metadata'] = image_metadata

    if 'pdf_text' in methods:
        pdf_text = extract_text_from_pdf(file_path)
        if pdf_text:
            results['pdf_text'] = pdf_text

    if 'steganography' in methods:
        stego_check = check_for_steganography(file_path)
        results['steganography'] = stego_check

    # Check if the 'extract_palette' method is selected
    if 'extract_palette' in methods:
        palette_result = extract_and_save_palette(file_path)
        if palette_result:
            results['palette'] = palette_result

    # Filter results if keyword is provided
    if keyword:
        filtered_results = {}
        for key, value in results.items():
            if isinstance(value, str) and keyword.lower() in value.lower():
                filtered_results[key] = value
            elif isinstance(value, list) and any(keyword.lower() in item.lower() for item in value):
                filtered_results[key] = [item for item in value if keyword.lower() in item.lower()]
        return filtered_results

    return results

# Function to run analysis and update GUI with results
def run_analysis():
    # Get the file path from the entry widget
    file_path = file_entry.get()

    # Check if file is selected
    if not file_path or not os.path.isfile(file_path):
        messagebox.showerror("Error", "Please select a valid file.")
        return
    
    # Get selected methods
    selected_methods = []
    if hash_var.get():
        selected_methods.append('hash')
    if binwalk_var.get():
        selected_methods.append('binwalk')
    if extract_zip_var.get():
        selected_methods.append('extract_zip_text')
    if strings_var.get():
        selected_methods.append('strings')
    if hexdump_var.get():
        selected_methods.append('hexdump')
    if entropy_var.get():
        selected_methods.append('entropy')
    if base64_var.get():
        selected_methods.append('base64')
    if metadata_var.get():
        selected_methods.append('metadata')
    if pdf_text_var.get():
        selected_methods.append('pdf_text')
    if steganography_var.get():
        selected_methods.append('steganography')
    if palette_var.get():
        selected_methods.append('extract_palette')

    # Perform analysis
    results = analyze_file(file_path, selected_methods, keyword_entry.get())
    
    # Clear the result text widget
    result_text.delete(1.0, tk.END)

    # Display results
    if results:
        result_text.insert(tk.END, str(results))
    else:
        result_text.insert(tk.END, "No results found.")

# Function to select a file
def select_file():
    file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
    file_entry.delete(0, tk.END)  # Clear previous text
    file_entry.insert(0, file_path)  # Insert selected file path

# Create GUI window
window = tk.Tk()
window.title("CTF Analysis Tool")

# Frame for file selection
frame1 = tk.Frame(window)
frame1.pack(pady=10)

file_label = tk.Label(frame1, text="Select File:")
file_label.pack(side=tk.LEFT, padx=5)

file_entry = tk.Entry(frame1, width=50)
file_entry.pack(side=tk.LEFT, padx=5)

select_button = tk.Button(frame1, text="Browse", command=select_file)
select_button.pack(side=tk.LEFT)

# Frame for analysis methods selection
frame2 = tk.Frame(window)
frame2.pack(pady=10)

hash_var = tk.IntVar()
binwalk_var = tk.IntVar()
extract_zip_var = tk.IntVar()
strings_var = tk.IntVar()
hexdump_var = tk.IntVar()
entropy_var = tk.IntVar()
base64_var = tk.IntVar()
metadata_var = tk.IntVar()
pdf_text_var = tk.IntVar()
steganography_var = tk.IntVar()
palette_var = tk.IntVar()  # Variable for palette extraction

hash_check = tk.Checkbutton(frame2, text="Hash", variable=hash_var)
hash_check.pack(side=tk.LEFT)

binwalk_check = tk.Checkbutton(frame2, text="Binwalk", variable=binwalk_var)
binwalk_check.pack(side=tk.LEFT)

extract_zip_check = tk.Checkbutton(frame2, text="Extract ZIP Text", variable=extract_zip_var)
extract_zip_check.pack(side=tk.LEFT)

strings_check = tk.Checkbutton(frame2, text="Strings", variable=strings_var)
strings_check.pack(side=tk.LEFT)

hexdump_check = tk.Checkbutton(frame2, text="Hex Dump", variable=hexdump_var)
hexdump_check.pack(side=tk.LEFT)

entropy_check = tk.Checkbutton(frame2, text="Entropy", variable=entropy_var)
entropy_check.pack(side=tk.LEFT)

base64_check = tk.Checkbutton(frame2, text="Base64 Decode/Encode", variable=base64_var)
base64_check.pack(side=tk.LEFT)

metadata_check = tk.Checkbutton(frame2, text="Image Metadata", variable=metadata_var)
metadata_check.pack(side=tk.LEFT)

pdf_text_check = tk.Checkbutton(frame2, text="PDF Text", variable=pdf_text_var)
pdf_text_check.pack(side=tk.LEFT)

steganography_check = tk.Checkbutton(frame2, text="Steganography", variable=steganography_var)
steganography_check.pack(side=tk.LEFT)

palette_check = tk.Checkbutton(frame2, text="Extract Image Palette", variable=palette_var)
palette_check.pack(side=tk.LEFT)

# Frame for keyword search
frame3 = tk.Frame(window)
frame3.pack(pady=10)

keyword_label = tk.Label(frame3, text="Search Keyword:")
keyword_label.pack(side=tk.LEFT)

keyword_entry = tk.Entry(frame3, width=50)
keyword_entry.pack(side=tk.LEFT, padx=5)

# Frame for results display
frame4 = tk.Frame(window)
frame4.pack(pady=10)

result_text = scrolledtext.ScrolledText(frame4, width=80, height=20)
result_text.pack()

# Run analysis button
analyze_button = tk.Button(window, text="Run Analysis", command=run_analysis)
analyze_button.pack(pady=10)

window.mainloop()
