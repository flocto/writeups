import requests

s = requests.Session()
href=""
url = "http://web.chal.csaw.io:5010"
for i in range(100):
    r = s.get(url+href)
    # print(r.text)
    q = r.text[r.text.rfind("href="):]
    q = q[:q.find(">")]
    # print(q)
    exec(q) # if no href, then nothing gets executed
    print(href, i)
r = s.get(url+href)
print(r.text) # flag here
print(s.cookies)