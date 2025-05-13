#!/usr/bin/env python3
import argparse
from socket import *
import struct
import time
from datetime import datetime
import sys

# Constants
HEADER_FORMAT = '!IIHH'  # Sequence Number, Acknowledgment Number, Flags, Receiver Window
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
DATA_SIZE = 992  # Application data size
PACKET_SIZE = DATA_SIZE + HEADER_SIZE  # Total packet size
TIMEOUT = 0.4  # 400ms timeout for retransmission

# Flag bit positions
SYN_FLAG = 1 << 3  # 0b1000
ACK_FLAG = 1 << 2  # 0b0100
FIN_FLAG = 1 << 1  # 0b0010
# RST_FLAG = 1 << 0  # 0b0001 (not used in this assignment)

def current_time():
    """
    Returns the current time formatted as a string.
    Used for logging connection and packet events.
    """
    return datetime.now().strftime("%H:%M:%S.%f")

def create_packet(seq, ack, flags, win, data=b''):
    """
    Creates a packet with the specified header fields and data.
    
    Arguments:
    seq - Sequence number for the packet
    ack - Acknowledgment number for the packet
    flags - Bit flags for SYN, ACK, FIN, etc.
    win - Receiver window size
    data - Application data to include (optional)
    
    Returns: Bytes object containing the header and data
    """
    header = struct.pack(HEADER_FORMAT, seq, ack, flags, win)
    return header + data

def parse_header(header):
    """
    Parses a packet header into its component fields.
    
    Arguments:
    header - Raw header bytes
    
    Returns: Tuple of (seq, ack, flags, win)
    """
    return struct.unpack(HEADER_FORMAT, header)

def parse_flags(flags):
    """
    Extracts individual flag bits from the flags field.
    
    Arguments:
    flags - The flags field from the header
    
    Returns: Tuple of boolean values (syn, ack, fin)
    """
    syn = bool(flags & SYN_FLAG)
    ack = bool(flags & ACK_FLAG)
    fin = bool(flags & FIN_FLAG)
    return syn, ack, fin

def server(ip, port, discard_seq=None):
    """
    Implements the server (receiver) side of the DRTP protocol.
    
    Arguments:
    ip - IP address to bind to
    port - Port number to listen on
    discard_seq - Optional sequence number to discard (for testing)
    """
    server_socket = socket(AF_INET, SOCK_DGRAM)
    server_socket.bind((ip, port))
    print('The server is ready to receive')

    # State tracking
    throughput_start_time = None
    total_data_received = 0
    expected_seq = 1
    discard_done = False

    while True:
        message, client_address = server_socket.recvfrom(PACKET_SIZE)
        seq, ack, flags, win = parse_header(message[:HEADER_SIZE])
        syn_flag, ack_flag, fin_flag = parse_flags(flags)

        # Connection establishment
        if syn_flag and not ack_flag:
            print("SYN packet is received")
            response_flags = SYN_FLAG | ACK_FLAG  # SYN-ACK
            server_socket.sendto(create_packet(0, seq, response_flags, 15), client_address)
            print("SYN-ACK packet is sent")
        
        # Connection acknowledgment
        elif ack_flag and not syn_flag and not fin_flag and throughput_start_time is None:
            print("ACK packet is received")
            throughput_start_time = time.time()
            print("Connection established")
        
        # Connection teardown
        elif fin_flag:
            print("FIN packet is received")
            response_flags = ACK_FLAG | FIN_FLAG  # FIN-ACK
            server_socket.sendto(create_packet(0, seq, response_flags, 0), client_address)
            print("FIN ACK packet is sent")
            break
        
        # Data packets
        else:
            # Discard test case - only discard once
            if discard_seq and seq == discard_seq and not discard_done:
                print(f"{current_time()} -- out-of-order packet {seq} is received")
                discard_done = True
                continue
            
            # Process in-order packets
            if seq == expected_seq:
                total_data_received += len(message) - HEADER_SIZE
                
                print(f"{current_time()} -- packet {seq} is received")
                response_flags = ACK_FLAG
                ack_packet = create_packet(0, seq, response_flags, 0)
                server_socket.sendto(ack_packet, client_address)
                print(f"{current_time()} -- sending ack for the received {seq}")
                expected_seq += 1
            else:
                # Out-of-order packet
                print(f"{current_time()} -- out-of-order packet {seq} is received")

    # Calculate and display throughput
    if throughput_start_time is not None:
        throughput_time = time.time() - throughput_start_time
        throughput = (total_data_received * 8) / throughput_time / 1_000_000  # Mbps
        print(f"The throughput is {throughput:.2f} Mbps")
    else:
        print("No data was transferred, can't calculate throughput")
    
    print("Connection Closes")

def client(ip, port, filename, window_size):
    """
    Implements the client (sender) side of the DRTP protocol.
    
    Arguments:
    ip - IP address of the server
    port - Port number of the server
    filename - File to send
    window_size - Maximum number of unacknowledged packets allowed
    """
    client_socket = socket(AF_INET, SOCK_DGRAM)
    client_socket.settimeout(TIMEOUT)

    # Establishing connection with retry
    print("Connection Establishment Phase:\n")
    syn_packet = create_packet(0, 0, SYN_FLAG, 0)
    max_retries = 5
    attempt = 0
    connected = False
    server_window = 0

    while attempt < max_retries and not connected:
        try:
            print("SYN packet is sent")
            client_socket.sendto(syn_packet, (ip, port))
            response, _ = client_socket.recvfrom(PACKET_SIZE)
            _, ack, flags, win = parse_header(response[:HEADER_SIZE])
            syn_flag, ack_flag, _ = parse_flags(flags)

            if syn_flag and ack_flag:
                print("SYN-ACK packet is received")
                client_socket.sendto(create_packet(0, ack, ACK_FLAG, 0), (ip, port))
                print("ACK packet is sent")
                print("Connection established\n")
                connected = True
                server_window = win
            else:
                print("Unexpected response during handshake")
                attempt += 1

        except timeout:
            print("Timeout waiting for SYN-ACK, retrying...")
            attempt += 1

    if not connected:
        print("Connection failed")
        return

    # Data transfer
    print("Data Transfer:\n")
    
    # Determine effective window size (min of client and server window)
    effective_window = min(window_size, server_window)
    
    try:
        with open(filename, 'rb') as f:
            seq = 1
            base = 1
            packets = {}  # Dictionary to store packets: seq -> packet
            
            # Read and send initial window of packets
            while base <= seq and (data := f.read(DATA_SIZE)):
                if seq < base + effective_window:
                    packet = create_packet(seq, 0, 0, 0, data)
                    packets[seq] = packet
                    client_socket.sendto(packet, (ip, port))
                    print(f"{current_time()} -- packet with seq = {seq} is sent, sliding window = {list(range(base, min(base + effective_window, seq + 1)))} ")
                    seq += 1
                
                # Try to receive ACKs
                try:
                    while True:
                        ack_response, _ = client_socket.recvfrom(PACKET_SIZE)
                        _, ack_num, response_flags, _ = parse_header(ack_response[:HEADER_SIZE])
                        _, ack_flag, _ = parse_flags(response_flags)

                        if ack_flag:
                            print(f"{current_time()} -- ACK for packet = {ack_num} is received")
                            if ack_num >= base:
                                # Remove acknowledged packets
                                for i in range(base, ack_num + 1):
                                    if i in packets:
                                        del packets[i]
                                base = ack_num + 1
                except timeout:
                    pass  # Expected timeout for non-blocking receive
            
            # Continue sending/receiving until all data is acknowledged
            while packets:
                # Timeout check - resend all unacknowledged packets
                print(f"{current_time()} -- RTO occurred")
                for seq_num in sorted(packets.keys()):
                    print(f"{current_time()} -- retransmitting packet with seq = {seq_num}")
                    client_socket.sendto(packets[seq_num], (ip, port))
                
                # Wait for ACKs
                try:
                    start_time = time.time()
                    while time.time() - start_time < TIMEOUT and packets:
                        client_socket.settimeout(TIMEOUT - (time.time() - start_time))
                        ack_response, _ = client_socket.recvfrom(PACKET_SIZE)
                        _, ack_num, response_flags, _ = parse_header(ack_response[:HEADER_SIZE])
                        _, ack_flag, _ = parse_flags(response_flags)

                        if ack_flag:
                            print(f"{current_time()} -- ACK for packet = {ack_num} is received")
                            if ack_num >= base:
                                # Remove acknowledged packets
                                for i in range(base, ack_num + 1):
                                    if i in packets:
                                        del packets[i]
                                base = ack_num + 1
                except timeout:
                    pass  # Expected timeout

        print("\nDATA Finished\n")

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return

    # Connection teardown
    print("Connection Teardown:\n")
    fin_packet = create_packet(0, 0, FIN_FLAG, 0)
    attempt = 0
    teardown_acknowledged = False

    while attempt < max_retries and not teardown_acknowledged:
        try:
            print("FIN packet is sent")
            client_socket.sendto(fin_packet, (ip, port))
            response, _ = client_socket.recvfrom(PACKET_SIZE)
            _, _, flags, _ = parse_header(response[:HEADER_SIZE])
            _, ack_flag, fin_flag = parse_flags(flags)

            if ack_flag and fin_flag:
                print("FIN ACK packet is received")
                print("Connection Closes")
                teardown_acknowledged = True
            else:
                print("Unexpected response during teardown")
                attempt += 1

        except timeout:
            print("Timeout waiting for FIN-ACK, retrying...")
            attempt += 1

    if not teardown_acknowledged:
        print("Teardown failed: no FIN-ACK received after retries.")

    client_socket.close()

def main():
    """
    Main function to parse command-line arguments and start the application
    in either server or client mode.
    """
    parser = argparse.ArgumentParser(description="DRTP file transfer application")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', '--server', action='store_true', help="Run as server")
    group.add_argument('-c', '--client', action='store_true', help="Run as client")
    parser.add_argument('-i', '--ip', type=str, required=True, help="IP address")
    parser.add_argument('-p', '--port', type=int, required=True, help="Port number")
    parser.add_argument('-f', '--file', type=str, help="File to send (required for client)")
    parser.add_argument('-w', '--window', type=int, default=3, help="Window size for client (default: 3)")
    parser.add_argument('-d', '--discard', type=int, help="Sequence number to discard (for testing)")

    args = parser.parse_args()

    # Validate port number
    if args.port < 1024 or args.port > 65535:
        print("Error: Port number must be in the range [1024, 65535]")
        sys.exit(1)

    try:
        if args.server:
            server(args.ip, args.port, args.discard)
        elif args.client:
            if not args.file:
                print("Error: Client mode requires --file argument.")
                sys.exit(1)
            client(args.ip, args.port, args.file, args.window)
    except KeyboardInterrupt:
        print("\nApplication terminated by user")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()