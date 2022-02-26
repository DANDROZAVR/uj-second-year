import socket
import logging
import sys
import os
import subprocess as subproc
import re
import time
import multiprocessing
import select
import binascii
import threading


DNS_HOST = '8.8.8.8'
HOST = ''
PORT = 5354
PORT_DNS = 53
timeout = 4
clients = dict()

cur_ind = 1

def good_hex(x):
    return hex(int(x))[2:].zfill(2)

def dns_forward(input_data, dns_sock):
    global cur_ind
    old_ind = input_data[0:2]
    str_data = ''.join([good_hex(cur_ind / 256), good_hex(cur_ind % 256)])
    data = binascii.unhexlify(str_data) + input_data[2:]
    cur_ind += 1
    if cur_ind == 65536:
        cur_ind = 1
    dns_sock.sendto(data, (DNS_HOST, PORT_DNS))
    clients[str_data] = (addr, old_ind)


def pop_client_addr(dns_response):
    id_tran = dns_response[0:4]
    r = clients[id_tran]
    del clients[id_tran]
    return r

wzor = [6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0]
def google_found(data):
    for i in range(12, 24):
        if data[i] != wzor[i - 12]:
            return False;
    return True

def change_google(data):
    n = len(data)
    new_data = data[:n-4] + b'\x33\x8D\x09\x1D'
    return new_data;

def dns_listener(s, dns_sock):
    while True:
        data, addr = dns_sock.recvfrom(1024)
        dns_response = binascii.hexlify(data).decode("utf-8")
        client_addr = pop_client_addr(dns_response)
        print(google_found(data))
        if (google_found(data)):
            data = change_google(data)
        s.sendto(client_addr[1] + data[2:], client_addr[0])
        print(f'Sent dns_ans [{data}] to {client_addr[0]}')
#synchro?#synchro?#synchro?

if __name__ == '__main__':
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((HOST, PORT))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_sock:
            thread = threading.Thread(target=dns_listener, args=(s, dns_sock))
            thread.start()
            while True:
                data, addr = s.recvfrom(1024)
                print(f'Recieved {data} from {addr}')
                dns_forward(data, dns_sock)

