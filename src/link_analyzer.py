import time
import requests
from base64 import urlsafe_b64encode
from bs4 import BeautifulSoup
import json
import os

def load_token_from_file():
    try:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        token_path = os.path.join(base_dir, "config", "token.json")
        with open(token_path, "r") as file:
            data = json.load(file)
            api_key = data.get("api_key")
            if api_key:
                return api_key
            else:
                raise ValueError("Brak klucza API w pliku token.json.")
    except FileNotFoundError:
        raise FileNotFoundError("Plik token.json nie istnieje w katalogu config.")
    except Exception as e:
        raise Exception(f"Błąd podczas wczytywania pliku token.json: {e}")

class LinkAnalyzer:
    def __init__(self, virustotal_api_key, delay=15):
        self.virustotal_api_key = virustotal_api_key
        self.delay = delay
        self.cache = {}

    def check_link_virustotal(self, link):
        if link in self.cache:
            print(f"Link '{link}' odczytany z pamięci podręcznej (cache).")
            return self.cache[link]
        time.sleep(self.delay)

        base64_link = urlsafe_b64encode(link.encode()).decode().strip('=')
        url = f'https://www.virustotal.com/api/v3/urls/{base64_link}'
        headers = {'x-apikey': self.virustotal_api_key}

        try:
            print(f"Sending request to VirusTotal: {url}")
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 404:
                print(f"VirusTotal: URL not found for {link} (404).")
                result = {
                    "status": "not_found",
                    "details": f"URL not found in VirusTotal: {link}"
                }
            elif response.status_code == 200:
                vt_data = response.json()
                analysis_results = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})

                suspicious_engines = []
                for engine, data in analysis_results.items():
                    if data.get('category') in ['suspicious', 'malicious']:
                        suspicious_engines.append({
                            "engine": engine,
                            "result": data.get('result'),
                            "category": data.get('category')
                        })

                if suspicious_engines:
                    print(f"Suspicious engines found for {link}: {suspicious_engines}")
                    result = {
                        "status": "suspicious",
                        "details": suspicious_engines
                    }
                else:
                    print(f"No suspicious or malicious results for {link}.")
                    result = {
                        "status": "clean",
                        "details": "No issues detected"
                    }
            else:
                print(f"Unexpected response status code: {response.status_code} for {link}.")
                result = {
                    "status": "error",
                    "details": f"Unexpected status code: {response.status_code}"
                }

        except requests.exceptions.RequestException as e:
            print(f"Error during request to VirusTotal: {e}")
            result = {
                "status": "error",
                "details": str(e)
            }

        self.cache[link] = result
        return result

    def analyze_page_content(self, url):
 
        try:
            print(f"Analyzing URL: {url}")
            head_response = requests.head(url, timeout=10)
            content_type = head_response.headers.get('Content-Type', '').lower()
            
            if 'text/html' not in content_type:
                print(f"Skipping unsupported content type: {content_type} for {url}")
                return []

            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                sensitive_keywords = ['password', 'credit card', 'cvv', 'ssn', 'login', 'email']
                flagged_data = []

                for form in soup.find_all('form'):
                    for input_tag in form.find_all('input'):
                        field_name = input_tag.get('name', '').lower()
                        if any(keyword in field_name for keyword in sensitive_keywords):
                            flagged_data.append(f"Form field: {field_name}")

                page_text = soup.get_text()
                for keyword in sensitive_keywords:
                    if keyword in page_text.lower():
                        flagged_data.append(f"Keyword in text: {keyword}")

                for a_tag in soup.find_all('a', href=True):
                    if any(keyword in a_tag.get_text().lower() for keyword in sensitive_keywords):
                        flagged_data.append(f"Link text: {a_tag.get_text()}")

                print(f"Flagged data for {url}: {flagged_data}")
                return flagged_data or ["No sensitive data found"]
            else:
                print(f"HTTP Error {response.status_code} for {url}")
                return [f"HTTP Error {response.status_code}"]
        except requests.exceptions.Timeout:
            print(f"Timeout occurred while analyzing: {url}")
            return [f"Timeout analyzing {url}"]
        except requests.exceptions.RequestException as e:
            print(f"Error analyzing page: {e}")
            return [f"Failed to analyze {url}: {str(e)}"]
        finally:
            print(f"Finished analyzing: {url}")