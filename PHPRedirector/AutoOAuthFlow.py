import argparse
import time
import re
import os
import requests
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# DON'T RUN THIS IN YOUR WEB ROOT AS IT WILL OUTPUT ACCESS TOKENS 
# TO A FILE CALLED "access_tokens.txt" IN THE SAME DIRECTORY. IF
# YOU DO THIS YOU MAY EXPOSE ACCESS TOKENS ON YOUR WEB SERVER.

# Initialize OAuth credentials as global variables
client_id = None
client_secret = None
redirect_uri = None
scope = None

# Initialize a set to store processed OAuth codes
processed_codes = set()

def complete_oauth_flow(auth_code):
    global client_id, client_secret, redirect_uri, scope

    if auth_code in processed_codes:
        # If the auth code has already been processed, skip processing
        return

    token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

    # Define the request parameters
    data = {
        "client_id": client_id,
        "scope": scope,
        "code": auth_code,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
        "client_secret": client_secret,
    }

    try:
        # Make a POST request to obtain the access and refresh tokens
        response = requests.post(token_url, data=data)

        # Check if the request was successful
        if response.status_code == 200:
            # Parse the JSON response to extract tokens
            token_data = response.json()
            access_token = token_data.get("access_token")
            refresh_token = token_data.get("refresh_token")
            print("\nAccess Token:", access_token)
            print("Refresh Token:", refresh_token)

            # Get the current date and time
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Write access tokens with timestamp to a file (append mode)
            print("\n[*] Appending access tokens to access_tokens.txt")
            with open("access_tokens.txt", "a") as token_file:  # Use "a" for append mode
                token_file.write(f"[{timestamp}] Access Token: {access_token}\n")
                token_file.write(f"[{timestamp}] Refresh Token: {refresh_token}\n")

            # Add the processed code to the set
            processed_codes.add(auth_code)
        else:
            print("[*] OAuth flow failed with status code:", response.status_code)
            print(response.text)
    except Exception as e:
        print("Error:", str(e))

class CodeFileHandler(FileSystemEventHandler):
    def on_modified(self, event):
        # Check if the event is a file and if it exists
        if event.is_directory or not os.path.exists(event.src_path):
            return

        # Define a regular expression pattern to match the entire OAuth code block
        oauth_code_pattern = r'OAuth Code:(.*?)\n\n\n'

        # Read the contents of the modified file (codes.txt)
        with open(event.src_path, 'r') as file:
            content = file.read()

            # Use regex to search for all OAuth code blocks in the content
            matches = re.findall(oauth_code_pattern, content, re.DOTALL)

            if matches:
                # Extract the last OAuth code block
                oauth_code_block = matches[-1].strip()
                code_detected = f"\n\n[*] Processed OAuth Code: {oauth_code_block}"

                # Check if the file is 'codes.txt' and delete it
                if os.path.basename(event.src_path) == 'codes.txt':
                    os.remove(event.src_path)
                    
                    if code_detected not in processed_codes:
                        print("\n[*] Detected new OAuth code. Now attempting to complete the OAuth flow...")
                        # Call the function to complete the OAuth flow
                        complete_oauth_flow(oauth_code_block)
                        processed_codes.add(code_detected)
                        print(code_detected)
                    
                    # Call the function to complete the OAuth flow
                    complete_oauth_flow(oauth_code_block)

def main():
    global client_id, client_secret, redirect_uri, scope

    parser = argparse.ArgumentParser(description="OAuth Flow Script")
    parser.add_argument("-client-id", required=True, help="Your OAuth Client ID")
    parser.add_argument("-secret", required=True, help="Your OAuth Client Secret")
    parser.add_argument("-redirect-uri", required=True, help="Your OAuth Redirect URI")
    parser.add_argument("-scope", required=True, help="OAuth Scope")
    args = parser.parse_args()

    client_id = args.client_id
    client_secret = args.secret
    redirect_uri = args.redirect_uri
    scope = args.scope

    path = "/home/site/wwwroot/"  # Directory where the 'codes.txt' file is located
    codes_file_path = os.path.join(path, "codes.txt")

    # Check if the codes.txt file exists and delete it
    if os.path.exists(codes_file_path):
        os.remove(codes_file_path)

    event_handler = CodeFileHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    observer.start()
    print("[*] Now watching for new OAuth codes written to", codes_file_path)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    

if __name__ == "__main__":
    main()
