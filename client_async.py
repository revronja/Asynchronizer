import asyncio
import aiohttp

class Scanner:
    def __init__(self):
       self.API_KEY = "key"
       self.BASE_URL = "https://www.virustotal.com/vtapi/v2/"
       self.SCAN_EP = "url/scan"
       self.Headers =  {
            'Content-Type': 'application/json',
            'apikey': self.API_KEY,
        }

    async def make_request(self, urls):
        for url in urls:
            print(f"making request to {self.BASE_URL}{self.SCAN_EP}{url}")
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.post(self.BASE_URL+'scan/', headers=self.Headers, data = '{"url": "%s"}' % url) as resp:
                    if resp.status == 200:
                        r = await resp.read()
                        data = r.decode("utf-8")
                        print(data)


if __name__ == "__main__":
    urls = ["https://www.google.com","https://www.apple.com"]
    loop = asyncio.get_event_loop()
    scanner = Scanner()
    loop.run_until_complete(scanner.make_request(urls))
