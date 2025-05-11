#!/usr/bin/env python3
# DATA2410 Reliable Transport Protocol (DRTP) - Reference Implementation
# This code demonstrates a working implementation of the protocol specifications

import argparse
import socket
import struct
import time
import sys
import os
import datetime
import select
import random

# Constants for the protocol
DEFAULT_WINDOW_SIZE = 3
DEFAULT_PORT = 8088
DEFAULT_IP = "127.0.0.1"
HEADER_SIZE = 8  # bytes
DATA_SIZE = 992  # bytes
PACKET_SIZE = HEADER_SIZE + DATA_SIZE  # 1000 bytes
TIMEOUT = 0.4  # 400 milliseconds

# Flag definitions
SYN_FLAG = 0b0010
ACK_FLAG = 0b0001
FIN_FLAG = 0b0100
RESET_FLAG = 0b1000

class DrptPacket:
    """
    Class that represents a DRTP packet with methods to serialize/deserialize
    """
    
    def __init__(self, seq_num=0, ack_num=0, flags=0, window=0, data=b''):
        """
        Initialize a DRTP packet with header fields and data
        
        Args:
            seq_num: Sequence number (16 bits)
            ack_num: Acknowledgment number (16 bits)
            flags: Control flags (16 bits, only 4 bits used)
            window: Receiver window size (16 bits)
            data: Application data (up to 992 bytes)
        """
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.flags = flags
        self.window = window
        self.data = data
    
    def pack(self):
        """
        Serializes the packet into a bytes object
        
        Returns:
            A bytes object representing the packet
        """
        # Pack header using network byte order (big-endian)
        header = struct.pack('!HHHH', self.seq_num, self.ack_num, self.flags, self.window)
        
        # Combine header and data
        return header + self.data
    
    @classmethod
    def unpack(cls, packet_bytes):
        """
        Deserializes a bytes object into a DrptPacket
        
        Args:
            packet_bytes: A bytes object representing the packet
            
        Returns:
            A DrptPacket object
        """
        # Extract header fields
        header = packet_bytes[:HEADER_SIZE]
        seq_num, ack_num, flags, window = struct.unpack('!HHHH', header)
        
        # Extract data if present
        data = packet_bytes[HEADER_SIZE:] if len(packet_bytes) > HEADER_SIZE else b''
        
        return cls(seq_num, ack_num, flags, window, data)
    
    def __str__(self):
        """
        String representation of the packet for debugging
        
        Returns:
            A string describing the packet
        """
        flags_str = ''
        if self.flags & SYN_FLAG:
            flags_str += 'SYN '
        if self.flags & ACK_FLAG:
            flags_str += 'ACK '
        if self.flags & FIN_FLAG:
            flags_str += 'FIN '
        if self.flags & RESET_FLAG:
            flags_str += 'RST '
        
        return f"SEQ={self.seq_num}, ACK={self.ack_num}, Flags=[{flags_str.strip()}], Window={self.window}, Data={len(self.data)} bytes"


class DrptSender:
    """
    Implements the sending logic for DRTP protocol with Go-Back-N
    """
    
    def __init__(self, ip, port, window_size):
        """
        Initialize the sender with connection parameters
        
        Args:
            ip: IP address of the receiver
            port: Port number of the receiver
            window_size: Size of the sliding window
        """
        self.receiver_ip = ip
        self.receiver_port = port
        self.window_size = window_size
        self.base = 1  # Base of the sliding window (first unacknowledged packet)
        self.next_seq_num = 1  # Next sequence number to use
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(TIMEOUT)
        self.packets = {}  # Buffer to store sent packets for potential retransmission
        self.receiver_window = 0  # Receiver's advertised window size
        self.connected = False
    
    def establish_connection(self):
        """
        Performs three-way handshake to establish connection
        
        Returns:
            True if connection established, False otherwise
        """
        print("\nConnection Establishment Phase:\n")
        
        # Create SYN packet
        syn_packet = DrptPacket(seq_num=0, flags=SYN_FLAG, window=self.window_size)
        
        # Send SYN packet
        self.socket.sendto(syn_packet.pack(), (self.receiver_ip, self.receiver_port))
        print("SYN packet is sent")
        
        try:
            # Wait for SYN-ACK packet
            response_data, _ = self.socket.recvfrom(PACKET_SIZE)
            syn_ack_packet = DrptPacket.unpack(response_data)
            
            # Validate SYN-ACK packet
            if (syn_ack_packet.flags & SYN_FLAG) and (syn_ack_packet.flags & ACK_FLAG):
                print("SYN-ACK packet is received")
                
                # Store receiver's window size
                self.receiver_window = syn_ack_packet.window
                
                # Adjust window size based on receiver's window
                self.window_size = min(self.window_size, self.receiver_window)
                
                # Send ACK packet
                ack_packet = DrptPacket(seq_num=1, ack_num=1, flags=ACK_FLAG, window=self.window_size)
                self.socket.sendto(ack_packet.pack(), (self.receiver_ip, self.receiver_port))
                print("ACK packet is sent")
                print("Connection established")
                self.connected = True
                return True
            else:
                print("Unexpected response during handshake")
                return False
        
        except socket.timeout:
            print("Connection failed")
            return False
    
    def send_file(self, file_path):
        """
        Sends a file using DRTP protocol with Go-Back-N
        
        Args:
            file_path: Path to the file to be sent
        
        Returns:
            True if file sent successfully, False otherwise
        """
        if not self.connected:
            print("Not connected, cannot send file")
            return False
        
        try:
            # Open file for reading in binary mode
            with open(file_path, 'rb') as file:
                print("\nData Transfer:\n")
                
                # Read and send file in chunks
                while True:
                    # If window is not full, send next packet
                    if self.next_seq_num < self.base + self.window_size:
                        # Read a chunk of data from file
                        data = file.read(DATA_SIZE)
                        
                        # If no more data, break
                        if not data:
                            break
                        
                        # Create data packet
                        packet = DrptPacket(seq_num=self.next_seq_num, flags=0, window=self.window_size, data=data)
                        
                        # Send packet
                        self.socket.sendto(packet.pack(), (self.receiver_ip, self.receiver_port))
                        
                        # Store packet for potential retransmission
                        self.packets[self.next_seq_num] = packet
                        
                        # Display current sliding window
                        window_content = "{" + ", ".join(str(i) for i in range(self.base, min(self.next_seq_num + 1, self.base + self.window_size))) + "}"
                        print(f"{datetime.datetime.now().time()} -- packet with seq = {self.next_seq_num} is sent, sliding window = {window_content}")
                        
                        # Move to next sequence number
                        self.next_seq_num += 1
                    
                    # Try to receive ACKs
                    self.receive_acks()
                
                # Wait for all packets to be acknowledged
                while self.base < self.next_seq_num:
                    self.receive_acks()
                
                print("DATA Finished")
                return True
                
        except FileNotFoundError:
            print(f"File {file_path} not found")
            return False
    
    def receive_acks(self):
        """
        Receives and processes acknowledgments, handles timeouts and retransmissions
        """
        try:
            # Try to receive an ACK
            response_data, _ = self.socket.recvfrom(PACKET_SIZE)
            ack_packet = DrptPacket.unpack(response_data)
            
            # Check if it's an ACK packet
            if ack_packet.flags & ACK_FLAG:
                print(f"{datetime.datetime.now().time()} -- ACK for packet = {ack_packet.ack_num} is received")
                
                # Update base
                if ack_packet.ack_num >= self.base:
                    self.base = ack_packet.ack_num + 1
                    
                    # Clean up acknowledged packets
                    keys_to_remove = [key for key in self.packets if key < self.base]
                    for key in keys_to_remove:
                        del self.packets[key]
        
        except socket.timeout:
            # Timeout occurred, retransmit all unacknowledged packets
            print(f"{datetime.datetime.now().time()} -- RTO occured")
            
            for seq_num in range(self.base, self.next_seq_num):
                if seq_num in self.packets:
                    print(f"{datetime.datetime.now().time()} -- retransmitting packet with seq = {seq_num:2d}")
                    self.socket.sendto(self.packets[seq_num].pack(), (self.receiver_ip, self.receiver_port))
    
    def terminate_connection(self):
        """
        Performs connection teardown
        
        Returns:
            True if connection terminated successfully, False otherwise
        """
        if not self.connected:
            return True
        
        print("\n\nConnection Teardown:\n")
        
        # Create FIN packet
        fin_packet = DrptPacket(seq_num=self.next_seq_num, flags=FIN_FLAG, window=self.window_size)
        
        # Send FIN packet
        self.socket.sendto(fin_packet.pack(), (self.receiver_ip, self.receiver_port))
        print("FIN packet packet is sent")
        
        try:
            # Wait for FIN-ACK packet
            response_data, _ = self.socket.recvfrom(PACKET_SIZE)
            fin_ack_packet = DrptPacket.unpack(response_data)
            
            # Validate FIN-ACK packet
            if (fin_ack_packet.flags & FIN_FLAG) and (fin_ack_packet.flags & ACK_FLAG):
                print("FIN ACK packet is received")
                print("Connection Closes")
                self.connected = False
                self.socket.close()
                return True
            else:
                print("Unexpected response during teardown")
                return False
        
        except socket.timeout:
            print("Teardown failed")
            return False


class DrptReceiver:
    """
    Implements the receiving logic for DRTP protocol
    """
    
    def __init__(self, ip, port, discard_seq=None):
        """
        Initialize the receiver with listening parameters
        
        Args:
            ip: IP address to bind to
            port: Port number to bind to
            discard_seq: Sequence number to discard (for testing)
        """
        self.ip = ip
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((ip, port))
        self.expected_seq_num = 1  # Next expected sequence number
        self.window_size = 15  # Receiver's window size
        self.client_address = None
        self.discard_seq = discard_seq
        self.discard_done = False  # Flag to track if we've already discarded the packet
        self.data_received = 0  # Total bytes received
        self.start_time = None  # Start time of data transfer
    
    def establish_connection(self):
        """
        Waits for and handles three-way handshake
        
        Returns:
            True if connection established, False otherwise
        """
        # Wait for SYN packet
        syn_data, client_address = self.socket.recvfrom(PACKET_SIZE)
        syn_packet = DrptPacket.unpack(syn_data)
        
        # Validate SYN packet
        if syn_packet.flags & SYN_FLAG:
            print("SYN packet is received")
            self.client_address = client_address
            
            # Send SYN-ACK packet
            syn_ack_packet = DrptPacket(seq_num=0, ack_num=0, flags=SYN_FLAG | ACK_FLAG, window=self.window_size)
            self.socket.sendto(syn_ack_packet.pack(), client_address)
            print("SYN-ACK packet is sent")
            
            # Wait for ACK packet
            ack_data, _ = self.socket.recvfrom(PACKET_SIZE)
            ack_packet = DrptPacket.unpack(ack_data)
            
            # Validate ACK packet
            if ack_packet.flags & ACK_FLAG:
                print("ACK packet is received")
                print("Connection established")
                self.start_time = time.time()
                return True
            else:
                print("Invalid ACK packet received")
                return False
        else:
            print("Invalid SYN packet received")
            return False
    
    def receive_file(self, output_dir="./"):
        """
        Receives a file using DRTP protocol
        
        Args:
            output_dir: Directory where received file will be saved
            
        Returns:
            True if file received successfully, False otherwise
        """
        # Create a temporary file to store received data
        output_file = os.path.join(output_dir, f"received_file_{int(time.time())}")
        
        with open(output_file, 'wb') as file:
            # Keep receiving until FIN packet is received
            while True:
                data, _ = self.socket.recvfrom(PACKET_SIZE)
                packet = DrptPacket.unpack(data)
                
                # Check if it's a FIN packet (connection teardown)
                if packet.flags & FIN_FLAG:
                    print("FIN packet is received")
                    
                    # Send FIN-ACK packet
                    fin_ack_packet = DrptPacket(seq_num=0, ack_num=packet.seq_num, flags=FIN_FLAG | ACK_FLAG, window=self.window_size)
                    self.socket.sendto(fin_ack_packet.pack(), self.client_address)
                    print("FIN ACK packet is sent")
                    
                    # Calculate throughput
                    end_time = time.time()
                    duration = end_time - self.start_time
                    throughput = (self.data_received * 8) / (duration * 1000000)  # Mbps
                    print(f"\nThe throughput is {throughput:.2f} Mbps")
                    print("Connection Closes")
                    
                    return True
                
                # Handle data packets
                if packet.seq_num == self.expected_seq_num:
                    # Check if we should discard this packet (for testing)
                    if self.discard_seq == packet.seq_num and not self.discard_done:
                        print(f"{datetime.datetime.now().time()} -- out-of-order packet {packet.seq_num} is received")
                        self.discard_done = True
                        continue
                    
                    # Expected packet received, process it
                    print(f"{datetime.datetime.now().time()} -- packet {packet.seq_num} is received")
                    
                    # Write data to file
                    if packet.data:
                        file.write(packet.data)
                        self.data_received += len(packet.data)
                    
                    # Send ACK
                    ack_packet = DrptPacket(seq_num=0, ack_num=packet.seq_num, flags=ACK_FLAG, window=self.window_size)
                    self.socket.sendto(ack_packet.pack(), self.client_address)
                    print(f"{datetime.datetime.now().time()} -- sending ack for the received {packet.seq_num} ")
                    
                    # Move window forward
                    self.expected_seq_num += 1
                
                else:
                    # Out-of-order packet, discard it
                    print(f"{datetime.datetime.now().time()} -- out-of-order packet {packet.seq_num} is received")
                    
                    # If the packet is before our expected sequence number, we might have lost the ACK
                    # Resend ACK for the highest in-order packet we've received
                    if packet.seq_num < self.expected_seq_num:
                        ack_packet = DrptPacket(seq_num=0, ack_num=self.expected_seq_num-1, flags=ACK_FLAG, window=self.window_size)
                        self.socket.sendto(ack_packet.pack(), self.client_address)


def validate_ip(ip):
    """
    Validates that the given string is a valid IP address
    
    Args:
        ip: IP address to validate
        
    Returns:
        The validated IP address
        
    Raises:
        argparse.ArgumentTypeError: If the IP address is invalid
    """
    try:
        socket.inet_aton(ip)
        return ip
    except socket.error:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {ip}")


def validate_port(port):
    """
    Validates that the given port number is valid
    
    Args:
        port: Port number to validate
        
    Returns:
        The validated port number as an integer
        
    Raises:
        argparse.ArgumentTypeError: If the port number is invalid
    """
    try:
        port = int(port)
        if 1024 <= port <= 65535:
            return port
        else:
            raise argparse.ArgumentTypeError(f"Port must be in range [1024, 65535]")
    except ValueError:
        raise argparse.ArgumentTypeError(f"Port must be an integer")


def main():
    """
    Main function to parse arguments and start the application in either server or client mode
    """
    parser = argparse.ArgumentParser(description="DATA2410 Reliable Transport Protocol (DRTP)")
    
    # Mode selection (server or client)
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("-s", "--server", action="store_true", help="Run in server mode")
    mode_group.add_argument("-c", "--client", action="store_true", help="Run in client mode")
    
    # Common arguments
    parser.add_argument("-i", "--ip", type=validate_ip, default=DEFAULT_IP, help="IP address")
    parser.add_argument("-p", "--port", type=validate_port, default=DEFAULT_PORT, help="Port number")
    
    # Client-specific arguments
    parser.add_argument("-f", "--file", type=str, help="File to transfer (client mode only)")
    parser.add_argument("-w", "--window", type=int, default=DEFAULT_WINDOW_SIZE, help="Sliding window size (client mode only)")