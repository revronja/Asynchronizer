import asyncio
import aiohttp

""""
10-27-19 sample responses
making request to https://www.virustotal.com/vtapi/v2/url/scanhttps://www.google.com
{"permalink": "https://www.virustotal.com/url/d0e196a0c25d35dd0a84593cbae0f38333aa58529936444ea26453eab28dfc86/analysis/1572210301/", 
"resource": "https://www.google.com/", "url": "https://www.google.com/", "response_code": 1, "scan_date": "2019-10-27 21:15:52", "scan_id": "d0e196a0c25d35dd0a84593cbae0f38333aa58529936444ea26453eab28dfc86-1572210301", 
"verbose_msg": "Scan request successfully queued, come back later for the report"}
making request to https://www.virustotal.com/vtapi/v2/url/scanhttps://www.apple.com
{"permalink": "https://www.virustotal.com/url/9e49cf4943550ed15085ca1e47265b880925c7a5f482b49af10662b0639b800c/analysis/1572210953/", 
"resource": "https://www.apple.com/", "url": "https://www.apple.com/", "response_code": 1, "scan_date": "2019-10-27 21:15:53", "scan_id": "9e49cf4943550ed15085ca1e47265b880925c7a5f482b49af10662b0639b800c-1572210953", 
"verbose_msg": "Scan request successfully queued, come back later for the report"}
""""

class Scanner:
    def __init__(self):
       self.API_KEY = "key"
       self.BASE_URL = "https://www.virustotal.com/vtapi/v2/"
       self.SCAN_EP = "url/scan"

    async def make_request(self, urls):
        for url in urls:
            print(f"making request to {self.BASE_URL}{self.SCAN_EP}{url}")
            params = {"url": url, "apikey": self.API_KEY}
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.post(self.BASE_URL+'url/scan', params=params ) as resp:
                    if resp.status == 200:
                        r = await resp.read()
                        data = r.decode("utf-8")
                        print(data)
                    else:
                        print(resp.status)


if __name__ == "__main__":
    urls = ["https://www.google.com","https://www.apple.com"]
    loop = asyncio.get_event_loop()
    scanner = Scanner()
    loop.run_until_complete(scanner.make_request(urls))
