import sys
import os
import json

base_dir = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
src_dir = os.path.join(base_dir, 'src')
if src_dir not in sys.path:
    sys.path.append(src_dir)

from src.imap_client import IMAPClient
from src.link_analyzer import LinkAnalyzer
from src.GUI.gui import LoginWindow

def load_config():

    base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    config_path = os.path.join(base_dir, 'config', 'token.json')  
    try:

        with open(config_path, 'r') as config_file:
            config = json.load(config_file)
            api_key = config.get("api_key")
            if not api_key:
                print("Brak klucza API w pliku token.json.")
                return None
            return api_key
    except FileNotFoundError:
        print(f"Nie znaleziono pliku token.json: {config_path}")
        return None
    except json.JSONDecodeError:
        print(f"Błąd w formacie pliku token.json: {config_path}")
        return None


def main():
    api_key = load_config()
    if not api_key:
        print("Nie udało się wczytać klucza API do VirusTotal.")
        return None


    imap_client_instance = IMAPClient(None, None, None, None)
    link_analyzer_instance = LinkAnalyzer(api_key)

    LoginWindow(imap_client_instance, link_analyzer_instance)
    return True

if __name__ == "__main__":
    main()
    
