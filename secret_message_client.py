# from scapy.all import *


# def send_secret_message(message, server_ip='127.0.0.1'):
#    for char in message:
#        ascii_value = ord(char)
#        send(IP(dst=server_ip) / UDP(dport=ascii_value))


# if __name__ == "__main__":
#    message = input("Enter your secret message: ")
#    send_secret_message(message)


from scapy.all import *

SERVER_IP = '127.0.0.1'


def send_secret_message(message):
    try:
        for char in message:
            ascii_value = ord(char)
            pkt = IP(dst=SERVER_IP) / UDP(dport=ascii_value)
            pkt.show()
            send(pkt)
    except Exception as e:
        print(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    message1 = input("Enter your secret message: ")
    send_secret_message(message1)
