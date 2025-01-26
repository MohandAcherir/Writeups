import os
import requests
import zipfile
from io import BytesIO
import time
import re
import subprocess


UPLOAD_URL = "http://challenges.hackday.fr:53073/secure_sharing"
flag = "HACKDAY{"


def generate_file_from_string(file_path, content):
    """Generates a file from the given string content."""
    with open(file_path, "w") as f:
        f.write(content)

def download_file(full_url, save_path):
    """Download the file from the given URL and save it to the specified path."""
    response = requests.get(full_url, stream=True)
    if response.status_code == 200:
        with open(save_path, "wb") as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        #print(f"[+] File downloaded and saved to {save_path}")
    else:
        print(f"[-] Failed to download file. Status code: {response.status_code}")

def upload_file_and_retrieve_zip(file_path):
    """Uploads a file to the server and retrieves the resulting ZIP."""
    tmps = 0
    with open(file_path, "rb") as f:
        # Send the file in a POST request
        tmps = int(time.time())
        response = requests.post(UPLOAD_URL, files={"file": f})

    if response.status_code == 200:
        #print("[+] File uploaded successfully.")
        pattern = rb"/download/\d+\.txt\.zip"
        matches = re.search(pattern, response.content)
        download_path = matches.group().decode("utf-8")
        download_file('http://challenges.hackday.fr:53073/'+download_path, 'payload.zip')
        return download_path, tmps  # Return the raw ZIP file content
    else:
        return upload_file_and_retrieve_zip(file_path)


def extract_zip(file_path, extract_to="extracted_files"):
    # Ensure the extraction directory exists
    os.makedirs(extract_to, exist_ok=True)
    
    # Open the ZIP file and extract all contents
    with zipfile.ZipFile(file_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)

def analyze_extracted_files(output_dir):
    """Analyze the extracted files (example: print contents)."""
    for root, dirs, files in os.walk(output_dir):
        for file in files:
            file_path = os.path.join(root, file)

def get_xxd_output(file_path):
    """Runs xxd on the given file and returns the output as a list of lines."""
    try:
        result = subprocess.run(["xxd", file_path], capture_output=True, text=True, check=True)
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        print(f"Error running xxd on {file_path}: {e}")
        return None

def xxd_continuous(file_path):
    with open(file_path, "rb") as file:
        data = file.read()

    hex_pairs = [f"{byte:02x}" for byte in data]
    
    return "".join(hex_pairs)


def find_until_mismatch(hex1, hex2):
    min_length = min(len(hex1), len(hex2))  # Compare up to the shortest length
    matched_chars = ""

    for i in range(min_length):
        if hex1[i] != hex2[i]:
            return i, matched_chars
        matched_chars += hex1[i]

    return min_length, matched_chars



def compare_hex_dumps(file1, file2):
    """Compares the xxd output of two files and prints differences."""
    dump1 = xxd_continuous(file1)
    dump2 = xxd_continuous(file2)
    position, matched_chars = find_until_mismatch(dump1, dump2)
    return position
    
def main():
    print("Guessing character by character...")
    flag = "HACKDAY{"
    for i in range(1, 45):
    	FLAG = flag
    	for c in range(256):
    		#print("HACKDAY{?")
    		flag += chr(c)
    		# generate the file
    		generate_file_from_string(f"payload.txt", flag)
    		zip_content, tmps = upload_file_and_retrieve_zip(f"payload.txt")
    		flag = FLAG
    		if zip_content:
    			#print(zip_content, tmps)
    			extract_zip("payload.zip", extract_to="extracted_files")
    			analyze_extracted_files("extracted_files")
    			res = compare_hex_dumps("extracted_files/flag.txt.enc", "extracted_files/payload.txt.enc")
    			if res >= 16+(i*2):
    				flag += chr(c)
    				print(flag)
    				break
    		    	# Step 2: Extract the ZIP file
    		    	# Step 3: Analyze the extracted files

if __name__ == "__main__":
    main()
