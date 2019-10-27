import asyncio
import aiohttp
import time


class URLScanner:
    def __init__(self):
       self.API_KEY = "key"
       self.BASE_URL = "https://www.virustotal.com/vtapi/v2/"
       self.SCAN_EP = "url/scan"
       self.REPORT_EP = "url/report"

    async def get_report(self, urls):
        """
        async function, an attribute of URLScanner class - response is ClientReponse type and is dict 
        retrieves a report from VT and if not exist makes call to submit func to scan it
        """
        for url in urls:
            print(f"making request to {self.BASE_URL}{self.REPORT_EP}{url}")
            params = {"resource": url, "apikey": self.API_KEY}
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.get(self.BASE_URL+'url/report', params=params ) as resp:
                    if resp.status == 200:
                        r = await resp.json()
                        print(r)
                        if r["response_code"] == 1:
                            print("existing report found. "+str(r["response_code"]))
                        elif if r["response_code"] == -2:
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
    


if __name__ == "__main__":
    urls = ["https://www.google.com","https://www.apple.com"]
    loop = asyncio.get_event_loop()
    scanner = URLScanner()
    loop.run_until_complete(scanner.get_report(urls))
