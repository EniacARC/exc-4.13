# from scapy.all import *

# CLIENT_IP = '127.0.0.1'  # Replace this with the actual IP address of the client


# def receive_secret_message():
#    message = ""
#    while True:
#        pkt = sniff(filter="udp and src host {}".format(CLIENT_IP), count=1)[0]
#        if UDP in pkt and pkt[UDP].dport > 0:
#            message += chr(pkt[UDP].dport)
#        else:
#            break
#    return message


# if __name__ == "__main__":
#    secret_message = receive_secret_message()
#    print("Received secret message:", secret_message)

from scapy.all import *


def f1(pkt):
    return UDP in pkt and pkt[UDP].sport == 12345 and IP in pkt


def receive_secret_message(server_port=12345):
    try:
        while True:
            # src port {server_port}
            pkt = sniff(lfilter=f1, count=1)[0]
            char = chr(pkt[UDP].dport)
            print(char, end='', flush=True)
    except KeyboardInterrupt:
        print("\nClient stopped.")


if __name__ == "__main__":
    receive_secret_message()
