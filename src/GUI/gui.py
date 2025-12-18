import tkinter as tk
from tkinter import messagebox, ttk, PhotoImage
import os
import sys
import queue
import threading
import time
from src.email_analyzer import EmailAnalyzer
from pathlib import Path

base_dir = getattr(sys, '_MEIPASS', os.path.abspath("."))

class LoginWindow:
    def __init__(self, imap_client, link_analyzer):
        self.imap_client = imap_client
        self.link_analyzer = link_analyzer
        self.result_queue = queue.Queue()
        self.email_analyzer = EmailAnalyzer(self.imap_client, self.link_analyzer, self.result_queue)
        self.after_id = None
        self.analysis_running = False
        self.setup_gui()
        

    def setup_gui(self):
        self.root = tk.Tk()
        self.root.title("Phishing Email Analyzer")
        self.root.geometry("400x500")
        self.root.configure(bg="#ffffff")
        icon_path = os.path.join(base_dir, 'images', 'icon.png')
        self.root.call("wm", "iconphoto", self.root._w, PhotoImage(file=icon_path))
        
        self.imap_server_var = tk.StringVar()
        self.imap_port_var = tk.StringVar()

        tk.Label(
            self.root,
            text="Phishing Email Analyzer",
            font=("Roboto", 20, "bold"),
            bg="#ffffff",
            fg="#4285F4"
        ).pack(pady=(20, 20))

        tk.Label(
            self.root,
            text="E-mail",
            font=("Roboto", 12),
            bg="#ffffff",
            fg="#202124"
        ).pack(pady=(5, 0))
        self.email_entry = tk.Entry(
            self.root,
            width=40,
            font=("Roboto", 12),
            relief="flat",
            highlightbackground="#dadce0",
            highlightthickness=1
        )
        self.email_entry.pack(pady=(0, 10))

        tk.Label(
            self.root,
            text="Hasło",
            font=("Roboto", 12),
            bg="#ffffff",
            fg="#202124"
        ).pack(pady=(5, 0))
        self.password_entry = tk.Entry(
            self.root,
            width=40,
            font=("Roboto", 12),
            relief="flat",
            show="*",
            highlightbackground="#dadce0",
            highlightthickness=1
        )
        self.password_entry.pack(pady=(0, 10))

        tk.Label(
            self.root,
            text="Wybierz serwer IMAP",
            font=("Roboto", 12),
            bg="#ffffff",
            fg="#202124"
        ).pack(pady=(5, 0))
        self.imap_options = {
            "Gmail": ("imap.gmail.com", "993"),
            "Onet": ("imap.poczta.onet.pl", "993"),
            "WP (Wirtualna Polska)": ("imap.wp.pl", "993"),
            "O2": ("imap.poczta.o2.pl", "993"),
            "Interia": ("imap.poczta.interia.pl", "993"),
            "Inna poczta...": ("", "")
        }

        self.imap_combo = ttk.Combobox(
            self.root,
            textvariable=self.imap_server_var,
            values=list(self.imap_options.keys()),
            state="readonly",
            font=("Roboto", 10)
        )
        self.imap_combo.pack(pady=(0, 10))
        self.imap_combo.bind("<<ComboboxSelected>>", self.update_imap_entry)

        self.custom_imap_frame = tk.Frame(self.root, bg="#ffffff")
        tk.Label(
            self.custom_imap_frame,
            text="Serwer IMAP (własny)",
            font=("Roboto", 10),
            bg="#ffffff",
            fg="#202124"
        ).pack(pady=(5, 0))
        self.custom_imap_entry = tk.Entry(
            self.custom_imap_frame,
            width=40,
            font=("Roboto", 10),
            relief="flat",
            highlightbackground="#dadce0",
            highlightthickness=1
        )
        self.custom_imap_entry.pack(pady=(0, 10))

        tk.Label(
            self.custom_imap_frame,
            text="Port IMAP (własny)",
            font=("Roboto", 10),
            bg="#ffffff",
            fg="#202124"
        ).pack(pady=(5, 0))
        self.custom_imap_port_entry = tk.Entry(
            self.custom_imap_frame,
            width=10,
            font=("Roboto", 10),
            relief="flat",
            highlightbackground="#dadce0",
            highlightthickness=1
        )
        self.custom_imap_port_entry.pack(pady=(0, 10))

        analyze_button = tk.Button(
            self.root,
            text="Zaloguj się i analizuj",
            font=("Roboto", 12, "bold"),
            bg="#4285F4",
            fg="white",
            activebackground="#3367D6",
            activeforeground="white",
            relief="flat",
            command=self.start_analysis
        )
        analyze_button.pack(pady=(20, 10))

        tk.Label(
            self.root,
            text="Zabezpiecz swoję dane!",
            font=("Roboto", 10, "italic"),
            bg="#ffffff",
            fg="#5f6368"
        ).pack(pady=(10, 20))

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    def update_imap_entry(self, event):
        selected_server = self.imap_server_var.get()
        server, port = self.imap_options[selected_server]

        if selected_server == "Inna poczta...":
            self.custom_imap_frame.pack(pady=(10, 5))
            self.custom_imap_entry.delete(0, tk.END)
            self.custom_imap_port_entry.delete(0, tk.END)
        else:
            self.custom_imap_frame.pack_forget()
            self.custom_imap_entry.insert(0, server)
            self.custom_imap_port_entry.insert(0, port)

    def start_analysis(self):
        server = self.custom_imap_entry.get() if self.imap_server_var.get() == "Inna poczta..." else self.imap_options[self.imap_server_var.get()][0]
        port = self.custom_imap_port_entry.get() if self.imap_server_var.get() == "Inna poczta..." else self.imap_options[self.imap_server_var.get()][1]
        email_address = self.email_entry.get()
        password = self.password_entry.get()
        
        
        self.imap_client.configure(server, port, email_address, password)

        if self.imap_client.login():
            if self.after_id:
                self.root.after_cancel(self.after_id)
            self.root.destroy()
            LoggedInWindow(self.imap_client, self.link_analyzer)
        else:
            messagebox.showerror("Błąd", "Nie udało się zalogować do skrzynki IMAP.")

    def process_queue(self):
            try:
                while not self.result_queue.empty():
                    message_type, title, message = self.result_queue.get(0)
                    if message_type == "info":
                        self.log_results(message)
                    elif message_type == "error":
                        messagebox.showerror(title, message)
                    self.result_queue.task_done()
            except queue.Empty:
                pass
            finally:
                if self.logged_window.winfo_exists():
                    self.after_id = self.logged_window.after(100, self.process_queue)


    def on_close(self):
        if self.after_id:
            self.root.after_cancel(self.after_id)
        self.root.destroy()

class LoggedInWindow:
    def __init__(self, imap_client, link_analyzer):
        self.imap_client = imap_client
        self.link_analyzer = link_analyzer
        self.analysis_running = False
        self.interval = 5
        self.skip_single_use_links = True

        self.result_queue = queue.Queue()
        self.email_analyzer = EmailAnalyzer(self.imap_client, self.link_analyzer, self.result_queue)
        self.after_id = None

        self.setup_logged_gui()

    def setup_logged_gui(self):
        self.logged_window = tk.Tk()
        self.logged_window.title("Phishing Analyzer")
        self.logged_window.geometry("400x500")
        self.logged_window.configure(bg="#ffffff")
        icon_path = os.path.join(base_dir, 'images', 'icon.png')
        self.logged_window.call("wm", "iconphoto", self.logged_window._w, PhotoImage(file=icon_path))
        
        self.ignore_links_var = tk.BooleanVar(value=True)

        tk.Label(
            self.logged_window,
            text="Panel Użytkownika",
            font=("Roboto", 20, "bold"),
            bg="#ffffff",
            fg="#4285F4"
        ).pack(pady=(20, 10))
                
        logout_button = tk.Button(
            self.logged_window,
            text="Wyloguj",
            font=("Roboto", 10, "bold"),
            bg="#d3d3d3",
            fg="black",
            relief="flat",
            command=self.logout
        )
        logout_button.place(relx=1.0, x=-10, y=10, anchor="ne")

        interval_frame = tk.Frame(self.logged_window, bg="#ffffff")
        interval_frame.pack(pady=(10, 5), fill=tk.X)

        tk.Label(
            interval_frame,
            text="Czas analizy (minuty):",
            font=("Roboto", 12),
            bg="#ffffff",
            fg="#202124"
        ).pack(side=tk.LEFT, padx=(10, 5))

        self.interval_entry = tk.Entry(
            interval_frame, width=10, font=("Roboto", 12), relief="flat"
        )
        self.interval_entry.insert(0, "5")
        self.interval_entry.pack(side=tk.LEFT, padx=(0, 5))

        self.interval_entry.bind("<Return>", lambda event: self.update_interval())

        email_count_frame = tk.Frame(self.logged_window, bg="#ffffff")
        email_count_frame.pack(pady=(10, 5), fill=tk.X)

        tk.Label(
            email_count_frame,
            text="Liczba wiadomości do pobrania:",
            font=("Roboto", 12),
            bg="#ffffff",
            fg="#202124"
        ).pack(side=tk.LEFT, padx=(10, 5))

        self.email_count_entry = tk.Entry(
            email_count_frame, width=10, font=("Roboto", 12), relief="flat"
        )
        self.email_count_entry.insert(0, "5")
        self.email_count_entry.pack(side=tk.LEFT, padx=(0, 5))

        self.email_count_entry.bind("<Return>", lambda event: self.update_email_count())


        status_frame = tk.Frame(self.logged_window, bg="#ffffff")
        status_frame.pack(pady=(10, 5), fill=tk.X)

        tk.Label(
            status_frame,
            text="Status:",
            font=("Roboto", 12, "bold"),
            bg="#ffffff",
            fg="#4285F4"
        ).pack(side=tk.LEFT, padx=(10, 5))

        self.status_label = tk.Label(
            status_frame,
            text="Nieaktywny",
            font=("Roboto", 12),
            bg="#ffffff",
            fg="#d00000"
        )
        self.status_label.pack(side=tk.LEFT)

        tk.Checkbutton(
            self.logged_window,
            text="Ignoruj linki z tokenami",
            font=("Roboto", 10),
            bg="#ffffff",
            variable=self.ignore_links_var,
            command=self.toggle_ignore_links_with_tokens
        ).pack(pady=(5, 5), anchor="w")
        
        button_frame = tk.Frame(self.logged_window, bg="#ffffff")
        button_frame.pack(pady=(20, 10))

        start_button = tk.Button(
            button_frame,
            text="Rozpocznij Analizę",
            font=("Roboto", 12, "bold"),
            bg="#34a853",
            fg="white",
            relief="flat",
            command=self.start_analysis
        )
        start_button.pack(side=tk.LEFT, padx=(5, 10))

        stop_button = tk.Button(
            button_frame,
            text="Zatrzymaj Analizę",
            font=("Roboto", 12, "bold"),
            bg="#ea4335",
            fg="white",
            relief="flat",
            command=self.stop_analysis
        )
        stop_button.pack(side=tk.LEFT, padx=(5, 10))



        results_frame = tk.Frame(self.logged_window, bg="#ffffff")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 20))

        self.results_text = tk.Text(
            results_frame,
            bg="#f8f9fa",
            font=("Roboto", 10),
            state=tk.DISABLED,
            wrap="none"  
        )
        self.results_text.grid(row=0, column=0, sticky="nsew")


        scrollbar_y = tk.Scrollbar(results_frame, orient="vertical", command=self.results_text.yview)
        scrollbar_y.grid(row=0, column=1, sticky="ns")  

        scrollbar_x = tk.Scrollbar(results_frame, orient="horizontal", command=self.results_text.xview)
        scrollbar_x.grid(row=1, column=0, sticky="ew")  


        self.results_text.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        results_frame.grid_rowconfigure(0, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)


        
        self.logged_window.protocol("WM_DELETE_WINDOW", self.on_close)
        self.logged_window.after(100, self.process_queue)
        self.logged_window.mainloop()


    def update_interval(self):
        try:
            new_interval = int(self.interval_entry.get())
            if new_interval > 0:
                self.interval = new_interval
                self.log_results(f"Czas analizy został zaktualizowany na {new_interval} minut.")
            else:
                raise ValueError
        except ValueError:
            messagebox.showerror("Błąd", "Podano nieprawidłowy czas analizy.")

    def update_email_count(self):
        try:
            email_count = int(self.email_count_entry.get())
            if email_count > 0:
                self.log_results(f"Liczba wiadomości do pobrania została zaktualizowana na {email_count}.")
            else:
                raise ValueError
        except ValueError:
            messagebox.showerror("Błąd", "Podano nieprawidłową liczbę wiadomości.")

    def toggle_ignore_links_with_tokens(self):
        if self.ignore_links_var.get():  # Odczyt aktualnej wartości
            self.log_results("Ignorowanie linków z tokenami zostało WŁĄCZONE.")
        else:
            self.log_results("Ignorowanie linków z tokenami zostało WYŁĄCZONE.")



    def process_queue(self):
        try:
            while not self.result_queue.empty():
                message_type, title, message = self.result_queue.get(0)
                if message_type == "info":
                    self.log_results(message)
                elif message_type == "error":
                    messagebox.showerror(title, message)
                self.result_queue.task_done()
        except queue.Empty:
            pass
        finally:
            if hasattr(self, "logged_window") and self.logged_window.winfo_exists():
                self.after_id = self.logged_window.after(100, self.process_queue)

    def update_link_behavior(self):
        self.skip_single_use_links = self.allow_single_use_links.get()
        if self.skip_single_use_links:
            self.log_results("Wyłączono analizę linków jednorazowych.")
        else:
            self.log_results("Włączono analizę linków jednorazowych.")
            

    def start_analysis(self):
        # Jeśli flaga jest ustawiona na True, oznacza to, że analiza już trwa.
        if self.analysis_running:
            messagebox.showwarning("Informacja", "Analiza jest już uruchomiona.")
            return

        # Tutaj ustawiamy self.analysis_running na True, 
        # żeby zasygnalizować, że analiza właśnie się zaczyna.
        self.analysis_running = True
        
        # Dalej konfigurujemy i odpalamy wątek.
        self.status_label.config(text="Aktywny", fg="#34a853")
        self.analysis_thread = threading.Thread(target=self.run_analysis_loop, daemon=True)
        self.analysis_thread.start()
        self.log_results("Analiza została rozpoczęta.")

    def stop_analysis(self):
        if self.analysis_running:
            self.analysis_running = False 
            self.status_label.config(text="Nieaktywny", fg="#d00000")
            if self.analysis_thread and self.analysis_thread.is_alive():
                self.analysis_thread.join(timeout=1)
            self.log_results("Analiza została zatrzymana.")

    def run_analysis_loop(self):
        while self.analysis_running:
            try:
                max_emails = int(self.email_count_entry.get())
                self.email_analyzer.analyze_emails(
                    self.imap_client.server,
                    self.imap_client.port,
                    self.imap_client.email,
                    self.imap_client.password,
                    folder_name="Phishing",
                    max_results=max_emails,
                    stop_flag=lambda: self.analysis_running,
                    ignore_links_with_tokens=self.ignore_links_var.get()
                )
            finally:
                if not self.analysis_running:
                    break
            time.sleep(self.interval * 60)



    def log_results(self, message):
        def update_gui():
            self.results_text.configure(state=tk.NORMAL)
            self.results_text.insert(tk.END, message + "\n")
            self.results_text.configure(state=tk.DISABLED)

        if hasattr(self, "logged_window") and self.logged_window.winfo_exists():
            self.logged_window.after(0, update_gui)


    def logout(self):
        if self.analysis_running:
            self.stop_analysis() 
        if self.imap_client.connected:
            self.imap_client.logout() 
        self.logged_window.destroy()  
        LoginWindow(self.imap_client, self.link_analyzer)


    def on_close(self):
        if self.after_id:
            self.logged_window.after_cancel(self.after_id)
        self.logged_window.destroy()
