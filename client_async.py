
import asyncio
import aiohttp
import time


class VirusTotal_Client():
    def __init__(self,key):
      self.URL_SCAN_EP = "url/scan"
      self.URL_REPORT_EP = "url/report"
      self.IP_REPORT_EP = "ip-address/report"
      self.BASE_URL = "https://www.virustotal.com/vtapi/v2/"
      self.REPORT_EP = "domain/report"
      self.FILE_SCAN_EP = "file/scan"
      self.FILE_REPORT_EP = "file/report"
      self.API_KEY = key
      self.BASE_URL = "https://www.virustotal.com/vtapi/v2/"

class URLScanner(VirusTotal_Client):
    async def get_report(self, urls):
        """
        async function, an attribute of URLScanner class - response is ClientReponse type and is dict 
        retrieves a report from VT and if not exist makes call to submit func to scan it
        """
        for url in urls:
            params = {"resource": url, "apikey": self.API_KEY}
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.get(self.BASE_URL+'url/report', params=params ) as resp:
                    if resp.status == 200:
                        r = await resp.json()
                        print(r)
                        if r["response_code"] == 1:
                            print("existing report found. "+str(r["response_code"]))
                        elif r["response_code"] == -2:
                            print("scan queued come back later! "+str(r["response_code"]))
                        else:
                            make_request(url)
                    elif resp.status == 204:
                        print("rate limited! waiting.")
                        time.sleep(60)

                    else:
                        print(resp.status)

    async def make_request(self, urls):
        """
        async function, an attribute of URLScanner class - response is ClientReponse type and is dict 
        subimts a URL to VT 
        """
        for url in urls:
            print(f"making request to {self.BASE_URL}{self.SCAN_EP}{url}")
            params = {"url": url, "apikey": self.API_KEY}
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.post(self.BASE_URL+'url/scan', params=params ) as resp:
                    if resp.status == 200:
                        r = await resp.json()
                        print(r)
                
                    elif resp.status == 204:
                        print("rate limited! waiting.")
                        time.sleep(60)

                    else:
                        print(resp.status)
    
class FileScanner(VirusTotal_Client):

    async def get_report(self, resources):
        """
        async function, an attribute of FileScanner class - response is ClientReponse type and is dict 
        retrieves a report from VT and if not exist makes call to submit func to scan it
        """
        for res in resources:
            print(f"making request to {self.BASE_URL}{self.REPORT_EP}{url}")
            params = {"resource": url, "apikey": self.API_KEY}
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.get(self.BASE_URL+'file/report', params=params ) as resp:
                    if resp.status == 200:
                        r = await resp.json()
                        print(r)
                        if r["response_code"] == 1:
                            print("existing report found. "+str(r["response_code"]))
                        elif r["response_code"] == -2:
                            print("scan queued come back later! "+str(r["response_code"]))
                        else:
                            make_request(url)
                    elif resp.status == 204:
                        print("rate limited! waiting.")
                        time.sleep(60)

                    else:
                        print(resp.status)

    async def make_request(self, resources):
        """
        async function, an attribute of FileScanner class - response is ClientReponse type and is dict 
        subimts a URL to VT 
        """
        for res in resources:
            print(f"making request to {self.BASE_URL}{self.SCAN_EP}{url}")
            params = {"resource": url, "apikey": self.API_KEY}
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.post(self.BASE_URL+'file/scan', params=params ) as resp:
                    if resp.status == 200:
                        r = await resp.json()
                        print(r)
                
                    elif resp.status == 204:
                        print("rate limited! waiting.")
                        time.sleep(60)

                    else:
                        print(resp.status)
    
class DomainScanner(VirusTotal_Client):

    async def get_report(self, domains):
        """
        async function, an attribute of DomainScanner class - response is ClientReponse type and is dict 
        retrieves a report from VT 
        """
        for dom in domains:
            print(f"making request to {self.BASE_URL}{self.REPORT_EP}{url}")
            params = {"domain": url, "apikey": self.API_KEY}
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.get(self.BASE_URL+'domain/report', params=params ) as resp:
                    if resp.status == 200:
                        r = await resp.json()
                        print(r)
                        if r["response_code"] == 1:
                            print("existing report found. "+str(r["response_code"]))
                        elif r["response_code"] == -2:
                            print("scan queued come back later! "+str(r["response_code"]))
                        else:
                            make_request(url)
                    elif resp.status == 204:
                        print("rate limited! waiting.")
                        time.sleep(60)

                    else:
                        print(resp.status)

class IPScanner(VirusTotal_Client):

    async def get_report(ips):
        """
        async function, an attribute of IPScanner class - response is ClientReponse type and is dict 
        retrieves a report from VT a
        """
        for ip in ips:
            print(f"making request to {self.BASE_URL}{self.REPORT_EP}{url}")
            params = {"ip": url, "apikey": self.API_KEY}
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.get(self.BASE_URL+'ip-address/report', params=params ) as resp:
                    if resp.status == 200:
                        r = await resp.json()
                        print(r)
                        if r["response_code"] == 1:
                            print("existing report found. "+str(r["response_code"]))
                        elif r["response_code"] == -2:
                            print("scan queued come back later! "+str(r["response_code"]))
                        else:
                            make_request(url)
                    elif resp.status == 204:
                        print("rate limited! waiting.")
                        time.sleep(60)

                    else:
                        print(resp.status)

    


if __name__ == "__main__":
  

    #  try:
    #     with open(os.getenv("VT-API")) as key:
    #          client = VirusTotal_Client(key)
    #  except:
    #     print('put your VT API KEY in ENV VAR VT-API')
    #     sys.exit()

    # parser = argparse.ArgumentParser(description='Virustotal Async Client for the tired SOC Analyst')
    # parser.add_argument("-o", "--output", help="output file for your report", action="store_true")
    
    # args = parser.parse_args()
    key="key"
    #client = VirusTotal_Client(key)
    urls = ["https://www.google.com","https://www.apple.com"]
    loop = asyncio.get_event_loop()
    scanner = URLScanner(key)
    loop.run_until_complete(scanner.get_report(urls))
