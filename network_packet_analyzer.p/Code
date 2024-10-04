import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, AsyncSniffer
import queue

packet_queue = queue.Queue()

def packet_callback(packet):
        packet_queue.put(packet.summary())

def update_text_area():
    if not packet_queue.empty():
        packet_summary = packet_queue.get()
        text_area.insert(tk.END, packet_summary + '\n')
        text_area.see(tk.END)
    
    # Scheduling the next update
    root.after(100, update_text_area)

def start_sniffing():
    packet_count = int(entry.get())
    status_label.config(text=f"Starting to capture {packet_count} packets...")
    
    # Using AsyncSniffer to sniff packets in a separate thread
    sniffer = AsyncSniffer(prn=packet_callback, count=packet_count)
    sniffer.start()

    # Scheduling the first update
    root.after(100, update_text_area)
    
    sniffer.join()
    status_label.config(text="Sniffing complete.")

# GUI
root = tk.Tk()
root.title("Packet Sniffer")

entry_label = tk.Label(root, text="Enter the number of packets you want to sniff:")
entry_label.pack(pady=5)

entry = tk.Entry(root)
entry.pack(pady=5)

start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing)
start_button.pack(pady=5)

status_label = tk.Label(root, text="")
status_label.pack(pady=5)

text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=70, height=20)
text_area.pack(pady=5)

root.mainloop()
