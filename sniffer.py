import threading
from scapy.all import sniff
import time

# Shared variable to store the packet count
packet_count = 0
# Lock for thread-safe access to shared variable
count_lock = threading.Lock()

# Function to handle each sniffed packet
def packet_handler(packet):
    global packet_count
    with count_lock:
        packet_count += 1

# Sniffer thread function
def packet_sniffer():
    print("Starting packet sniffer...")
    sniff(prn=packet_handler)

# Main program
def main():
    # Create and start the sniffer thread
    sniffer_thread = threading.Thread(target=packet_sniffer)
    sniffer_thread.daemon = True  # This makes the thread exit when the main program exits
    sniffer_thread.start()

    # Main thread monitors the packet count
    try:
        while True:
            with count_lock:
                print(f"Total packets received: {packet_count}")
            time.sleep(5)  # Update every 5 seconds
    except KeyboardInterrupt:
        print("Stopping packet sniffer...")

if __name__ == "__main__":
    main()