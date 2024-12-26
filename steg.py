import subprocess
import os
from PIL import Image
import pyexiv2
import re

def check_file_type(filename):
    """ Check the file type using 'file' command """
    try:
        result = subprocess.run(['file', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8').strip()
    except Exception as e:
        return f"Error checking file type: {e}"

def check_strings(filename):
    """ Extract strings from image using 'strings' command """
    try:
        result = subprocess.run(['strings', '-n', '7', '-t', 'x', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8').strip()
    except Exception as e:
        return f"Error extracting strings: {e}"

def check_exif_metadata(filename):
    """ Check EXIF metadata using pyexiv2 """
    try:
        metadata = pyexiv2.ImageMetadata(filename)
        metadata.read()
        return metadata
    except Exception as e:
        return f"Error reading EXIF metadata: {e}"

def run_binwalk(filename):
    """ Run binwalk to extract hidden files from image """
    try:
        result = subprocess.run(['binwalk', '-Me', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8').strip()
    except Exception as e:
        return f"Error running binwalk: {e}"

def check_png_chunks(filename):
    """ Run pngcheck to check for broken chunks """
    try:
        result = subprocess.run(['pngcheck', '-vtp7f', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8').strip()
    except Exception as e:
        return f"Error running pngcheck: {e}"

def extract_lsb_data(filename):
    """ Extract LSB data from image (stub method) """
    # Ideally, you can implement LSB extraction here or use a tool that extracts LSBs
    return "LSB data extraction is not implemented here."

def check_rgb_values(filename):
    """ Check RGB values for hidden ASCII or data """
    try:
        image = Image.open(filename)
        pixels = image.getdata()
        rgb_values = list(pixels)[:100]  # Just checking the first 100 pixels for example
        extracted_text = ''.join(chr(pixel[0] & 0xFF) for pixel in rgb_values if 32 <= (pixel[0] & 0xFF) <= 126)  # Convert to ASCII
        return extracted_text if extracted_text else "No ASCII text found in RGB values."
    except Exception as e:
        return f"Error checking RGB values: {e}"

def steghide_extract(filename, password=None):
    """ Extract data using steghide """
    try:
        command = ['steghide', 'extract', '-sf', filename]
        if password:
            command += ['-p', password]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8').strip()
    except Exception as e:
        return f"Error running steghide: {e}"

def analyze_image(filename):
    print(f"Analyzing {filename}...\n")

    # 1. File Type
    print(f"1. File Type: {check_file_type(filename)}\n")

    # 2. Strings
    print(f"2. Strings: {check_strings(filename)}\n")

    # 3. EXIF Metadata
    print(f"3. EXIF Metadata: {check_exif_metadata(filename)}\n")

    # 4. Binwalk (for embedded files)
    print(f"4. Binwalk: {run_binwalk(filename)}\n")

    # 5. PNG Chunks (Check for broken chunks)
    print(f"5. PNG Chunks: {check_png_chunks(filename)}\n")

    # 6. LSB Data (Placeholder for LSB extraction method)
    print(f"6. LSB Data: {extract_lsb_data(filename)}\n")

    # 7. RGB Values (Check for hidden ASCII data in RGB values)
    print(f"7. RGB Values: {check_rgb_values(filename)}\n")

    # 8. Steghide (If password is found, try extracting)
    print(f"8. Steghide Extract: {steghide_extract(filename)}\n")

if __name__ == '__main__':
    filename = input("Enter the path to the image file: ")
    if os.path.exists(filename):
        analyze_image(filename)
    else:
        print("File does not exist!")
