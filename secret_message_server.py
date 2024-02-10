from scapy.all import *


def is_empty_udp__packet(pkt):
    """
    Checks if the UDP packet is empty.

    :param pkt: The packet to be checked.
    :type pkt: scapy.packet.Packet

    :return: True if the UDP packet is empty, False otherwise.
    :rtype: bool
    """
    payload = pkt[UDP].payload
    return isinstance(payload, Padding) and (payload.load == b'\x00' * len(payload.load))


def f1(pkt):
    """
    Helper function to filter packets.

    :param pkt: The packet to be filtered.
    :type pkt: scapy.packet.Packet

    :return: True if the packet matches the filter conditions, False otherwise.
    :rtype: bool
    """
    return IP in pkt and UDP in pkt and is_empty_udp__packet(pkt)


def receive_secret_message():
    """
    Receives a secret message by sniffing UDP packets and extracting characters.

    :return: The received secret message.
    :rtype: str
    """
    try:
        while True:
            # src port {server_port}
            pkt = sniff(lfilter=f1, count=1)[0]
            char = chr(pkt[UDP].dport)
            print(char, end='')
    except KeyboardInterrupt:
        print("\nClient stopped.")


if __name__ == "__main__":
    receive_secret_message()
