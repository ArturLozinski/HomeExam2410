import argparse
from socket import *
import struct
import time
from datetime import datetime
import sys

# Constants
HEADER_FORMAT = '!IIHH'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
DATA_SIZE = 992
PACKET_SIZE = DATA_SIZE + HEADER_SIZE 
TIMEOUT = 0.4 # 400ms

# Returns the time of day to keep track of connection establishment time etc. Code from github.com/safiqul/
def current_time():
    return time.ctime(time.time())

# Creates packet, unpack packet and sets flags
def create_packet(seq, ack, flags, win, data=b''):
    header = struct.pack(HEADER_FORMAT, seq, ack, flags, win)
    return header + data

def parse_header(header):
    return struct.unpack(HEADER_FORMAT, header)

def parse_flags(flags):
    syn = flags & (1 << 3)
    ack = flags & (1 << 2)
    fin = flags & (1 << 1)
    return syn, ack, fin

# Server side code based on the udpserver.py from github.com/safiqul/
def server(ip, port):
    server_socket = socket(AF_INET, SOCK_DGRAM)
    server_socket.bind((ip, port))
    print('The server is ready to recieve')

    throughput_start_time = None
    total_data_recieved = 0

    while True:
        message, client_address = server_socket.recvfrom(PACKET_SIZE)
        seq, ack, flags, win = parse_header(message[:HEADER_SIZE])
        syn, ack_flag, fin = parse_flags(flags)

        if syn:
            print("SYN packet is recieved")
            response_flags = (1 << 3) | (1 << 2) # SYN-ACK
            server_socket.sendto(create_packet(0, seq, response_flags, 15))
            print("SYN-ACK packet is sent")
        elif ack: 
            print("ACK packet is recieved")
            throughput_start_time = time.time()
            print("Connection established")
        elif fin:
            print("FIN packet is recieved")
            print("FIN packet is received")
            response_flags = (1 << 2) | (1 << 1)  # FIN-ACK
            server_socket.sendto(create_packet(0, seq, response_flags, 0), client_address)
            print("FIN ACK packet is sent")
            break
        else:
            total_data_recieved += len(message) - HEADER_SIZE
            print(f"{current_time()} -- packet {seq} received")
            response_flags = (1 << 2) # ACk
            server_socket.sendto(create_packet(0, seq, flags, 0), client_address)
            print(f"{current_time()} sending ACK for the recieved {seq}")

    throughput_time = time.time() - throughput_start_time
    throughput = (total_data_recieved * 8) / throughput_time / 1_000_000 # Mbps
    print("The througput is {throughput:.2f} Mbps")
    print("Connection closes")

def client(ip, port, filename, window_size):
    client_socket = socket(AF_INET, SOCK_DGRAM)
    client_socket.settimeout(TIMEOUT)

    # Establishing connection with retry
    print("Connection Establishment Phase:")
    syn_packet = create_packet(0, 0, 1 << 3, 0)
    max_retries = 5
    attempt = 0
    connected = False

    while attempt < max_retries and not connected:
        try:
            print(f"Attempt {attempt + 1}: SYN packet is sent")
            client_socket.sendto(syn_packet, (ip, port))
            response, _ = client_socket.recvfrom(PACKET_SIZE)
            _, ack, flags, win = parse_header(response[:HEADER_SIZE])
            syn, ack_flag, _ = parse_flags(flags)

            if syn and ack_flag:
                print("SYN-ACK packet received")
                client_socket.sendto(create_packet(0, ack, 1 << 2, 0), (ip, port))
                print("ACK packet is sent")
                print("Connection established successfully")
                connected = True
            else:
                print("Unexpected response during handshake")

        except timeout:
            print("Timeout waiting for SYN-ACK, retrying...")
            attempt += 1

    if not connected:
        print("Failed to establish connection after retries.")
        return

    # Data transfer
    print("\nData Transfer:")
    with open(filename, 'rb') as f:
        seq = 1
        base = 1
        packets = []
        window = min(window_size, win)

        while True:
            while len(packets) < window and (data := f.read(DATA_SIZE)):
                packet = create_packet(seq, 0, 0, 0, data)
                packets.append(packet)
                client_socket.sendto(packet, (ip, port))
                print(f"{current_time()} -- Sent packet seq={seq}, window={list(range(base, seq + 1))}")
                seq += 1

            try:
                ack_response, _ = client_socket.recvfrom(PACKET_SIZE)
                _, ack_num, response_flags, _ = parse_header(ack_response[:HEADER_SIZE])
                _, ack_flag, _ = parse_flags(response_flags)

                if ack_flag:
                    print(f"{time.strftime('%H:%M:%S')} -- ACK for packet={ack_num} received")
                    base = ack_num + 1
                    packets = [pkt for pkt in packets if parse_header(pkt[:HEADER_SIZE])[0] >= base]
            except socket.timeout:
                print("Timeout: Resending unacknowledged packets")
                for pkt in packets:
                    seq_num, _, _, _ = parse_header(pkt[:HEADER_SIZE])
                    client_socket.sendto(pkt, (ip, port))
                    print(f"{time.strftime('%H:%M:%S')} -- Resent packet seq={seq_num}")

            if base == seq and not packets:
                break

    print("\nData transfer complete.")

    # Teardown with retry
    print("\nConnection Teardown Phase:")
    fin_packet = create_packet(0, 0, 1 << 1, 0)
    attempt = 0
    teardown_acknowledged = False

    while attempt < max_retries and not teardown_acknowledged:
        try:
            print(f"Attempt {attempt + 1}: Sending FIN")
            client_socket.sendto(fin_packet, (ip, port))
            response, _ = client_socket.recvfrom(PACKET_SIZE)
            _, _, flags, _ = parse_header(response[:HEADER_SIZE])
            _, ack_flag, fin_flag = parse_flags(flags)

            if ack_flag and fin_flag:
                print("FIN-ACK received. Connection closed.")
                teardown_acknowledged = True
            else:
                print("Unexpected response during teardown")

        except socket.timeout:
            print("Timeout waiting for FIN-ACK, retrying...")
            attempt += 1

    if not teardown_acknowledged:
        print("Teardown failed: no FIN-ACK received after retries.")

    client_socket.close()

def main():
    parser = argparse.ArgumentParser(description="UDP client/server with custom handshake and data transfer.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', '--server', action='store_true', help="Run as server")
    group.add_argument('-c', '--client', action='store_true', help="Run as client")
    parser.add_argument('-i', '--ip', type=str, required=True, help="IP address")
    parser.add_argument('-p', '--port', type=int, required=True, help="Port number")
    parser.add_argument('-f', '--file', type=str, help="File to send (required for client)")
    parser.add_argument('-w', '--window', type=int, default=5, help="Window size for client (default: 5)")

    args = parser.parse_args()

    if args.server:
        server(args.ip, args.port)
    elif args.client:
        if not args.file:
            print("Client mode requires --file argument.")
            sys.exit(1)
        client(args.ip, args.port, args.file, args.window)

if __name__ == '__main__':
    main()