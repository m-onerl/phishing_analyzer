import threading


class EmailAnalyzer:
    def __init__(self, imap_client, link_analyzer, result_queue):
        self.imap_client = imap_client
        self.link_analyzer = link_analyzer
        self.result_queue = result_queue

    def analyze_emails(self, server, port, email, password, folder_name="Phishing", max_results=5, stop_flag=None, ignore_links_with_tokens=True):
        try:
            self.imap_client.configure(server, port, email, password)
            if not self.imap_client.login():
                self.result_queue.put(("error", "Error", "Failed to login to IMAP server."))
                return

            self.imap_client.create_folder_if_not_exists(folder_name)
            emails = self.imap_client.fetch_emails(max_results=max_results)
            if not emails:
                self.result_queue.put(("info", "No Emails", "No emails found in the inbox."))
                return

            for email_data in emails:
                email_id, message = email_data[:2]
                if stop_flag and not stop_flag(): 
                    break

                body, is_html = self.imap_client.parse_email_content(message)
                links = self.imap_client.extract_links(body, is_html)

                flagged_links = []
                for link in links:
                    if not ignore_links_with_tokens and "token" in link:
                        continue

                    result = self.link_analyzer.check_link_virustotal(link)
                    if result["status"] in ["suspicious", "malicious"]:
                        flagged_links.append(link)

                if flagged_links:
                    self.imap_client.move_email_to_folder(email_id, folder_name, flagged_links)
                    self.result_queue.put(
                        ("info", "Przeniesiono wiadomość", f"Wiadomość UID {email_id} została przeniesiona do folderu '{folder_name}' z podejrzanymi linkami.")
                    )
                else:
                    self.result_queue.put(
                        ("info", "Brak akcji", f"Wiadomość UID {email_id} nie zawierała podejrzanych linków i nie została przeniesiona.")
                    )

        except Exception as e:
            self.result_queue.put(("error", "Błąd", f"Wystąpił nieoczekiwany błąd: {e}"))
        finally:
            self.imap_client.logout()


    @staticmethod
    def is_single_use_link(url):

        single_use_keywords = ['reset', 'token', 'auth', 'verify']
        return any(keyword in url.lower() for keyword in single_use_keywords)

    def start_analysis_thread(self, server, port, email, password, folder_name="Phishing"):

        def run_analysis():
            self.analyze_emails(server, port, email, password, folder_name)

        threading.Thread(target=run_analysis, daemon=True).start()
