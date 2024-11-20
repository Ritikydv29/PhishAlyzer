import streamlit as st
import numpy as np
import pickle
from urllib.parse import urlparse
import requests
from datetime import datetime
import re
import ipaddress
import re
from urllib.parse import urlparse, urljoin
from requests.exceptions import SSLError, Timeout

# Feature extraction functions
def get_domain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain

def having_ip(url):
    try:
        ipaddress.ip_address(url)
        ip = 1
    except:
        ip = 0
    return ip

def have_at_sign(url):
    return 1 if "@" in url else 0

def get_length(url):
    return 0 if len(url) < 54 else 1

def get_depth(url):
    s = urlparse(url).path.split('/')
    depth = sum(1 for part in s if len(part) != 0)
    return depth

def redirection(url):
    pos = url.rfind('//')
    if pos > 6:
        return 1 if pos > 7 else 0
    return 0

def http_domain(url):
    domain = urlparse(url).netloc
    return 1 if 'https' in domain else 0

def tiny_url(url):
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                          r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                          r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                          r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                          r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                          r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                          r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                          r"tr\.im|link\.zip\.net"
    return 1 if re.search(shortening_services, url) else 0

def prefix_suffix(url):
    return 1 if '-' in urlparse(url).netloc else 0 

def web_traffic(url):
    try:
        querystring = {"domain": url}
        headers = {
            "X-RapidAPI-Key": "cd4733fedbmsh6f2cfc21cf195f2p1d088djsn84e6c824c74e",
            "X-RapidAPI-Host": "similar-web.p.rapidapi.com"
        }
        response = requests.get("https://similar-web.p.rapidapi.com/get-analysis", headers=headers, params=querystring)
        data = response.json()
        rank = data['GlobalRank']['Rank']
        rank = int(rank)
    except (requests.exceptions.RequestException, ValueError, KeyError):
        rank = 1
    return 1 if rank < 100000 else 0

def iframe(response):
    return 1 if not re.findall(r"[<iframe>|<frameBorder>]", response.text) else 0

def mouse_over(response):
    return 1 if re.findall("<script>.+onmouseover.+</script>", response.text) else 0

def right_click(response):
    return 1 if not re.findall(r"event.button ?== ?2", response.text) else 0

def forwarding(response):
    return 1 if len(response.history) > 2 else 0


def sanitize_url(url):
    # If the URL does not contain a protocol, add 'http://'
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Correct malformed URLs by ensuring proper domain and path separation
    parsed_url = urlparse(url)
    # If there's no domain, it's not a valid URL, return None or raise error
    if not parsed_url.netloc:
        return None
    
    # If path and domain are concatenated incorrectly, fix it
    if parsed_url.netloc.startswith('mail.printakid.com'):
        # Remove any problematic concatenations here
        return None  # You can handle this specific case by returning None or another value

    # Use urljoin to properly join base domain with path (if path is malformed)
    correct_url = urljoin(url, parsed_url.path)

    return correct_url

def get_http_response(url):
    try:
        # Sanitize the URL before making the request
        sanitized_url = sanitize_url(url)
        
        if sanitized_url is None:
            # st.error("URL seems malformed or unreachable.")
            return None
        
        st.write(f"Making request to: {sanitized_url}")  # Debugging: Print the sanitized URL
        response = requests.get(sanitized_url, timeout=5)  # Set a timeout of 5 seconds
        return response
    except requests.exceptions.RequestException as e:
        # st.error(f"Error: {e}")
        return None
def extract_features(url):
    features = []
    features.append(having_ip(url))
    features.append(have_at_sign(url))
    features.append(get_length(url))
    features.append(get_depth(url))
    features.append(redirection(url))
    features.append(http_domain(url))
    features.append(tiny_url(url))
    features.append(prefix_suffix(url))

    dns, dns_age, dns_end = 0, 0, 0
    features.append(dns)
    features.append(dns_age)
    features.append(dns_end)
    features.append(web_traffic(url))

    response = get_http_response(url)
    if response:
        features.append(iframe(response))
        features.append(mouse_over(response))
        features.append(right_click(response))
        features.append(forwarding(response))
    elif response is None:
        return 0
    else:
        features.extend([0, 0, 0, 0])  # Default values if response is None

    return features

def predict_phishing(features):
    # Load the model
    with open('mlp_model.pkl', 'rb') as file:
        loaded_model = pickle.load(file)

    # Make predictions
    new_data = np.array([features])
    prediction = loaded_model.predict(new_data)
    
    # Debugging output: Check the prediction type and value
    print(f"Prediction type: {type(prediction)}")  # Check the type of prediction
    print(f"Prediction value: {prediction}")  # Print the prediction value

    # Ensure prediction is a scalar or array and return appropriately
    if isinstance(prediction, np.ndarray):
        return prediction[0]  # If it's an array, return the first element
    else:
        return prediction  # If it's a scalar, return it directly

def main():
    st.title('Phishing URL Detector')
    st.write("Enter a URL to check if it's phishing or not.")
    
    # Input URL
    url = st.text_input("Enter URL:")
    
    if st.button("Check"):
        # Extract features
        st.write("Extracting features...")
        try:
            features = extract_features(url)
            # st.write(f"Extracted features: {features}")  # Debugging line to see the extracted features
            if features==0:
                st.write("Prediction made:")
                st.error("Phishing Alert! This URL is classified as phishing.")
                return
                
            # Make prediction
            st.write("Predicting...")
            prediction = predict_phishing(features)
            # st.write(f"Prediction result: {prediction}")  # Debugging line to see what the model predicts
            
            # Display prediction
            if prediction == 1:
                st.write("Prediction made:")
                st.success("No Phishing Detected. This URL seems safe.")
            else:
                st.write("Prediction made:")
                st.error("Phishing Alert! This URL is classified as phishing.")
        
        except Exception as e:
            st.write("Prediction made:")
            st.error(f"An error occurred during prediction: {str(e)}")

if __name__ == '__main__':
    main()
