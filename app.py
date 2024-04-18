from pcapng import FileScanner
from httprequest import HTTPRequest
import re

def FindHttpRequestIndex(packet_str):
    regex_pattern = r"(?:GET|POST|PUT|DELETE|PATCH|HEAD) \/.+ HTTP\/1\.1\\r\\n"
    
    match = re.search(regex_pattern, packet_str)
    if match:
        return match.start()
    else:
        return -1

def test():
    with open(r"C:\Users\maxim\OneDrive\Desktop\Programming\Projects_Work\Pickup_Files\server\mixed.pcapng", 'rb') as pcap:
        scanner = FileScanner(pcap)
        
        for packet in scanner:
            if hasattr(packet, 'packet_data') == False:
                continue
            packet_str = str(packet.packet_data)
            
            http_request_index = FindHttpRequestIndex(packet_str)
            if http_request_index == -1:
                continue
            
            http_request_string = packet_str[http_request_index:]
            http_request = HTTPRequest(http_request_string)




if __name__ == "__main__":
    test()