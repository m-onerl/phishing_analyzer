import imaplib
import email
from email import message_from_bytes
import re
from datetime import datetime
import time
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlunparse


class IMAPClient:
    def __init__(self, server=None, port=None, email=None, password=None):
        self.server = server
        self.port = port
        self.email = email
        self.password = password
        self.mail = None
        self.connected = False
        
    def configure(self, server, port, email, password):
        self.server = server
        self.port = port
        self.email = email
        self.password = password

    def clean_url(self, url):
        try:
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                return url
            cleaned_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', '', ''))
            return cleaned_url
        except Exception as e:
            print(f"Error cleaning URL {url}: {e}")
            return url

    def is_valid_url(self, url):
        try:
            parsed_url = urlparse(url)
            return bool(parsed_url.scheme in ['http', 'https'] and parsed_url.netloc)
        except Exception as e:
            print(f"Error validating URL {url}: {e}")
            return False

    def login(self):
        try:
            self.mail = imaplib.IMAP4_SSL(self.server, self.port)
            self.mail.login(self.email, self.password)
            print("Połączono z serwerem IMAP.")
            return True
        except Exception as e:
            print("Błąd połączenia z IMAP:", e)
            return False


    def fetch_emails(self, max_results=5):
        try:
            self.mail.select("inbox")
            status, messages = self.mail.search(None, 'ALL')
            if status != "OK":
                print("Nie udało się pobrać wiadomości")
                return []

            message_ids = messages[0].split()[-max_results:]
            email_contents = []

            for email_id in message_ids:
                email_id_str = email_id.decode()
                status, msg_data = self.mail.fetch(email_id_str, "(RFC822)")
                if status != "OK":
                    print(f"Błąd podczas pobierania wiadomości {email_id_str}")
                    continue

                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = message_from_bytes(response_part[1]) 
                        email_contents.append((email_id_str, msg))

            return email_contents

        except Exception as e:
            print(f"Błąd podczas pobierania wiadomości e-mail: {e}")
            return []
        
    def parse_email_content(self, msg):
        if not isinstance(msg, email.message.Message):
            raise ValueError("Expected an email.message.Message object")

        body = ""
        is_html = False
        if msg.is_multipart():
            parts = []
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/html":
                    is_html = True
                if content_type in ["text/plain", "text/html"]:
                    try:
                        parts.append(part.get_payload(decode=True).decode())
                    except Exception as e:
                        print(f"Błąd dekodowania treści: {e}")
            body = "\n".join(parts)
        else:
            body = msg.get_payload(decode=True).decode()

        return body, is_html

    def normalize_url(self, url):
        try:
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:  
                print(f"Nieprawidłowy URL: {url}")
                return url

            trivial_paths = ['/Z', '/A', '/1', '/index', '/default']

            if parsed_url.path in trivial_paths:
                normalized_url = urlunparse((parsed_url.scheme, parsed_url.netloc, '', '', '', ''))
            else:
                normalized_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', '', ''))

            return normalized_url
        except Exception as e:
            print(f"Błąd podczas normalizacji URL: {e}")
            return url

    def extract_links(self, body, is_html=False):

        if is_html:
            return self.extract_links_from_html(body)
        else:
            return self.extract_links_from_text(body)


    def extract_links_from_html(self, body):

        try:
            soup = BeautifulSoup(body, 'html.parser')
            links = []
            for a_tag in soup.find_all('a', href=True):
                raw_url = a_tag['href']
                normalized_url = self.normalize_url(raw_url)
                if normalized_url not in links:
                    links.append(normalized_url)
            return links
        except Exception as e:
            print(f"Błąd podczas wyciągania linków z HTML: {e}")
            return []

    def extract_links_from_text(self, body):
        try:
            raw_links = re.findall(r'http[s]?://[^\s<>"]+|www\.[^\s<>"]+', body)
            links = []
            for raw_url in raw_links:
                normalized_url = self.normalize_url(raw_url)
                if normalized_url not in links:
                    links.append(normalized_url)
            return links
        except Exception as e:
            print(f"Błąd podczas wyciągania linków z tekstu: {e}")
            return []

    def create_folder_if_not_exists(self, folder_name="Phishing"):
        try:
            result, folders = self.mail.list()
            folder_names = [folder.decode().split(' "/" ')[1] for folder in folders]
            if folder_name not in folder_names:
                self.mail.create(folder_name)
                print(f"Utworzono folder: {folder_name}")
            else:
                print(f"Folder '{folder_name}' już istnieje.")
        except Exception as e:
            print(f"Błąd podczas tworzenia folderu '{folder_name}': {e}")

    def move_email_to_folder(self, email_id, folder_name="Phishing", sensitive_info=None):
        try:
            if not email_id or not email_id.isdigit():
                print(f"Invalid email ID: {email_id}")
                return

            print(f"Fetching email ID: {email_id}")
            status, data = self.mail.fetch(email_id, '(RFC822)')
            if status != 'OK' or not data:
                print(f"Failed to fetch email with ID {email_id}. Status: {status}")
                return

            for response_part in data:
                if isinstance(response_part, tuple):
                    try:
                        msg = email.message_from_bytes(response_part[1])


                        sensitive_info_text = ", ".join(sensitive_info) if sensitive_info else "No sensitive inputs detected"
                        new_subject = f"{msg.get('Subject', 'No Subject')} [PHISHING - Detected Inputs: {sensitive_info_text}]"

                        print(f"Original Subject: {msg.get('Subject', 'No Subject')}")
                        print(f"New Subject: {new_subject}")

                        if "Subject" in msg:
                            msg.replace_header("Subject", new_subject)
                        else:
                            msg["Subject"] = new_subject

                        self.create_folder_if_not_exists(folder_name)
                        append_status, _ = self.mail.append(folder_name, '', None, msg.as_bytes())
                        if append_status != 'OK':
                            print(f"Failed to append email ID {email_id} to folder '{folder_name}'.")
                            return


                        delete_status, _ = self.mail.store(email_id, '+FLAGS', '\\Deleted')
                        if delete_status != 'OK':
                            print(f"Failed to mark email ID {email_id} as deleted.")
                            return

                        self.mail.expunge()
                        print(f"Successfully moved email ID {email_id} to folder '{folder_name}'.")
                    except Exception as e:
                        print(f"Error processing email ID {email_id}: {e}")
                        continue
        except Exception as e:
            print(f"Unexpected error while moving email ID {email_id}: {e}")


    def logout(self):
        if self.mail:
            try:
                self.mail.logout()
            finally:
                self.mail = None 


