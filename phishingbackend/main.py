from flask import Flask, request, jsonify
import re
from urllib.parse import urlparse

app = Flask(__name__)

# File paths to the phishing databases
IP_FILE = 'phishing-IPs-ACTIVE.txt'
DOMAIN_FILE = 'ALL-phishing-domains.lst'
LINK_FILE = 'phishing-links-ACTIVE.txt'

# Function to check if the input is an IP address
def is_ip(input_string):
    # Simple regex to match an IP address format (IPv4)
    return bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', input_string))

# Function to check if the input is a valid URL
def is_url(input_string):
    # Check if the input string is a valid URL with http(s)
    return bool(re.match(r'^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}(/.*)?$', input_string))

# Function to read and check a file for a match
def check_file_for_match(file_path, search_string):
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if search_string == line.strip():  # Exact match
                    return True
    except FileNotFoundError:
        return False
    return False

@app.route('/check', methods=['POST'])
def check_vulnerability():
    # Get the input URL or IP from the request JSON
    data = request.get_json()
    print("Received data:", data)  # Print the incoming data for debugging
    input_string = data.get('url', '').strip()

    # Validate input
    if not input_string:
        response = {'message': 'No URL/IP provided'}
        print("Response being sent:", response)  # Print the response
        return jsonify(response), 400

    # If the URL doesn't start with 'http://' or 'https://', prepend 'http://'
    if is_url(input_string) and not input_string.startswith(('http://', 'https://')):
        input_string = 'http://' + input_string

    # Now check if the input is an IP address or URL
    if is_ip(input_string):
        # Check if the IP exists in the phishing IP list
        if check_file_for_match(IP_FILE, input_string):
            response = {'message': 'Vulnerable IP found! Do not access this IP.'}
            print("Response being sent:", response)  # Print the response
            return jsonify(response), 200
        else:
            response = {'message': 'This IP seems safe.'}
            print("Response being sent:", response)  # Print the response
            return jsonify(response), 200

    elif is_url(input_string):
        # Extract the domain part from the URL (excluding http:// or https://)
        parsed_url = urlparse(input_string)
        domain = parsed_url.netloc  # Extract the domain part (without http(s)://)

        # Check the domain against the phishing domain list
        if check_file_for_match(DOMAIN_FILE, domain):
            response = {'message': 'Vulnerable domain found! Do not access this domain.'}
            print("Response being sent:", response)  # Print the response
            return jsonify(response), 200

        # Check if the exact full URL exists in the phishing links list (ignoring parameters)
        url_without_params = parsed_url.scheme + '://' + parsed_url.netloc + parsed_url.path
        if check_file_for_match(LINK_FILE, url_without_params):
            response = {'message': 'Vulnerable link found! Do not click on this link.'}
            print("Response being sent:", response)  # Print the response
            return jsonify(response), 200
        else:
            response = {'message': 'This URL seems safe.'}
            print("Response being sent:", response)  # Print the response
            return jsonify(response), 200

    else:
        response = {'message': 'Invalid input format.'}
        print("Response being sent:", response)  # Print the response
        return jsonify(response), 400

if __name__ == '__main__':
    app.run(debug=True)
