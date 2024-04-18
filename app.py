from pcapng import FileScanner
from httprequest import HTTPRequest

def test():
    with open(r"C:\Users\maxim\OneDrive\Desktop\Programming\Projects_Work\Pickup_Files\server\mixed.pcapng", 'rb') as pcap:
        scanner = FileScanner(pcap)
        
        for block in scanner:
            print(str(block) + "\n")
            if hasattr(block, 'packet_data') == False:
                continue
            block_str = str(block.packet_data)
            method_index = block_str.find("GET")
            if method_index == -1:
                continue
            http_request_string = block_str[method_index:]
            http_request = HTTPRequest(http_request_string)




if __name__ == "__main__":
    test()