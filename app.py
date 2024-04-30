from scapy.all import *
from scapy.layers.http import HTTPRequest
from HttpRequestBuilder import HTTPRequestBuilder
from concurrent.futures import ThreadPoolExecutor
import re
import requests
def FindHttpRequestIndex(packet_str):
    regex_pattern = r"(?:GET|POST|PUT|DELETE|PATCH|HEAD) \/.+ HTTP\/1\.1\\r\\n"
    
    match = re.search(regex_pattern, packet_str)
    if match:
        return match.start()
    else:
        return -1

def test():
    packets = rdpcap(r"C:\Users\maxim\OneDrive\Desktop\Programming\Projects_Work\Pickup_Files\server\pcap_files\testfile.pcapng")

    for packet in packets:
        if packet.haslayer(HTTPRequest) and (IP in packet or IPv6 in packet): # type: ignore
            httpRequest = HTTPRequestBuilder(packet)

            try:
                print(httpRequest.dst_url)
                response = requests.request(method=httpRequest.method, url=httpRequest.dst_url, data=httpRequest.body, headers=httpRequest.headers)
                print(response._content)
            except Exception as e:
                print(e)

if __name__ == "__main__":
    test()