# client.py

from scapy.all import sniff
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext

SERVER_IP = '127.0.0.1'
SERVER_PORT = 9999

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def packet_callback(packet):
    try:
        summary = packet.summary()
        sock.sendall(summary.encode())
        text_area.insert(tk.END, summary + '\n')
        text_area.yview(tk.END)
    except:
        pass

def start_sniffing():
    sniff(prn=packet_callback, store=0)

def connect_to_server():
    try:
        sock.connect((SERVER_IP, SERVER_PORT))
    except Exception as e:
        print(f"Error: {e}")

root = tk.Tk()
root.title("👁️‍🗨️ Packet Sniffer Client")
root.geometry("750x500")
root.configure(bg="#0f0f0f")

title = tk.Label(root, text="Client Sniffer",
                 bg="#0f0f0f", fg="white", font=("Segoe UI", 18, "bold"))
title.pack(pady=10)

text_area = scrolledtext.ScrolledText(root,
                                      wrap=tk.WORD,
                                      bg="#1a1a1a",
                                      fg="white",
                                      insertbackground='white',
                                      font=("Segoe UI", 12),
                                      borderwidth=0)
text_area.pack(expand=True, fill='both', padx=20, pady=10)

btn = tk.Button(root, text="Start Sniffing",
                command=lambda: threading.Thread(target=start_sniffing, daemon=True).start(),
                bg="#222222", fg="white",
                font=("Segoe UI", 12, "bold"),
                activebackground="#333333",
                activeforeground="white",
                padx=10, pady=5)
btn.pack(pady=10)

threading.Thread(target=connect_to_server, daemon=True).start()
root.mainloop()
