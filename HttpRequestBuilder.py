from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6


class HTTPRequestBuilder:
    def __init__(self, packet):
        self.http_request = packet.getlayer('HTTPRequest')
        self.method = self.http_request.Method.decode("utf-8")

        self.headers = self.http_request.fields.copy()

        self.dst_url = self.getDestinationUrl(packet)

        self.body = None
        if packet.haslayer(Raw):
            self.body = packet[Raw].load

    def getDestinationUrl(self, packet):
        dst_path = self.http_request.Path.decode('utf-8')

        if self.headers["Host"]:
            dst_host = self.headers["Host"].decode()
        else:
            dst_ip = packet[IP].dst if IP in packet else "[" + packet[IPv6].dst + "]"

            if TCP in packet:
                dst_port = packet[TCP].dport
                dst_host = str(dst_ip) + ":" + str(dst_port)
            else:
                dst_host = str(dst_ip)

        return "http://" + dst_host + dst_path

    def __str__(self):
        return str(self.http_request)
