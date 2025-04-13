# server.py

import socket
import threading
import tkinter as tk
from tkinter import ttk

HOST = '0.0.0.0'
PORT = 9999

clients = []

def handle_client(conn, addr, tree):
    with conn:
        while True:
            try:
                data = conn.recv(4096).decode()
                if not data:
                    break
                tree.insert('', 'end', values=(addr[0], data))
            except ConnectionResetError:
                break

def accept_clients(server_socket, tree):
    while True:
        conn, addr = server_socket.accept()
        clients.append(conn)
        threading.Thread(target=handle_client, args=(conn, addr, tree), daemon=True).start()

def start_server(tree):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    threading.Thread(target=accept_clients, args=(server_socket, tree), daemon=True).start()

def create_gui():
    root = tk.Tk()
    root.title("🧠 Packet Sniffer Server")
    root.geometry("900x550")
    root.configure(bg="#0f0f0f")

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview",
                    background="#1a1a1a",
                    foreground="white",
                    fieldbackground="#1a1a1a",
                    rowheight=30,
                    font=('Segoe UI', 12))
    style.configure("Treeview.Heading",
                    background="#0f0f0f",
                    foreground="white",
                    font=('Segoe UI', 14, 'bold'))
    style.map("Treeview", background=[('selected', '#333333')])

    title = tk.Label(root, text="🌐 Live Packet Sniffer Server",
                     bg="#0f0f0f", fg="white", font=("Segoe UI", 18, "bold"))
    title.pack(pady=10)

    columns = ('Client IP', 'Packet Info')
    tree = ttk.Treeview(root, columns=columns, show='headings')
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, anchor='w', width=420)

    tree.pack(fill='both', expand=True, padx=20, pady=10)
    start_server(tree)

    root.mainloop()

if __name__ == '__main__':
    create_gui()
