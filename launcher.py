from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import messagebox, ttk


HOST = "127.0.0.1"
PORT = 8080
URL = f"http://{HOST}:{PORT}"
BASE_DIR = Path(__file__).resolve().parent


def port_is_open() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.25)
        return sock.connect_ex((HOST, PORT)) == 0


def browser_choices() -> list[str]:
    choices = ["System Default"]
    candidates = {
        "Chrome": ["chrome", "google-chrome"],
        "Edge": ["msedge", "microsoft-edge"],
        "Firefox": ["firefox"],
        "Safari": ["safari"],
    }
    for name, commands in candidates.items():
        for command in commands:
            try:
                webbrowser.get(command)
                choices.append(name)
                break
            except webbrowser.Error:
                continue
    return choices


class Launcher(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Campus PKI RA Launcher")
        self.geometry("520x300")
        self.resizable(False, False)
        self.server_process: subprocess.Popen[str] | None = None

        self.columnconfigure(0, weight=1)
        frame = ttk.Frame(self, padding=24)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.columnconfigure(0, weight=1)

        ttk.Label(frame, text="Campus PKI Registration Authority", font=("Segoe UI", 16, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(
            frame,
            text="Activate the local web server, then use the browser-based administration console.",
            wraplength=460,
        ).grid(row=1, column=0, sticky="w", pady=(8, 18))

        ttk.Label(frame, text="Browser").grid(row=2, column=0, sticky="w")
        self.browser_var = tk.StringVar(value="System Default")
        self.browser_box = ttk.Combobox(frame, textvariable=self.browser_var, values=browser_choices(), state="readonly")
        self.browser_box.grid(row=3, column=0, sticky="ew", pady=(4, 16))

        self.status_var = tk.StringVar(value=f"Server is off. Target: {URL}")
        ttk.Label(frame, textvariable=self.status_var).grid(row=4, column=0, sticky="w", pady=(0, 16))

        buttons = ttk.Frame(frame)
        buttons.grid(row=5, column=0, sticky="w")
        ttk.Button(buttons, text="Activate Server", command=self.activate).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(buttons, text="Open Web App", command=self.open_browser).grid(row=0, column=1, padx=(0, 10))
        ttk.Button(buttons, text="Stop Server", command=self.stop_server).grid(row=0, column=2)

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def activate(self) -> None:
        if port_is_open():
            self.status_var.set(f"Server is already running at {URL}")
            self.open_browser()
            return

        app_path = BASE_DIR / "app.py"
        self.server_process = subprocess.Popen(
            [sys.executable, str(app_path)],
            cwd=str(BASE_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        self.status_var.set("Starting local web server...")
        threading.Thread(target=self.wait_then_open, daemon=True).start()

    def wait_then_open(self) -> None:
        for _ in range(40):
            if port_is_open():
                self.status_var.set(f"Server is running at {URL}")
                self.open_browser()
                return
            time.sleep(0.25)
        self.status_var.set("Server did not start. Check whether port 8080 is already in use.")
        messagebox.showerror("Startup failed", "The local web server did not start on 127.0.0.1:8080.")

    def open_browser(self) -> None:
        choice = self.browser_var.get()
        try:
            if choice == "System Default":
                webbrowser.open(URL)
            else:
                browser_map = {
                    "Chrome": "chrome",
                    "Edge": "msedge",
                    "Firefox": "firefox",
                    "Safari": "safari",
                }
                webbrowser.get(browser_map.get(choice, "")).open(URL)
        except webbrowser.Error:
            webbrowser.open(URL)

    def stop_server(self) -> None:
        if self.server_process and self.server_process.poll() is None:
            self.server_process.terminate()
            self.server_process = None
            self.status_var.set("Server stopped.")
        elif port_is_open():
            self.status_var.set("A server is running on port 8080, but it was not started by this launcher.")
        else:
            self.status_var.set("Server is already off.")

    def on_close(self) -> None:
        if self.server_process and self.server_process.poll() is None:
            if messagebox.askyesno("Stop server?", "Stop the local RA web server before closing?"):
                self.stop_server()
        self.destroy()


if __name__ == "__main__":
    Launcher().mainloop()
