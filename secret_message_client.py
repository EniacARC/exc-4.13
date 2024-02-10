from scapy.all import *

SERVER_IP = '127.0.0.1'


def send_secret_message(message):
    """
    Sends a secret message by converting each character of the message to its ASCII value and sending it as a UDP packet.

    :param message: The secret message to be sent.
    :type message: str

    :return: None
    :rtype: None
    """
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
