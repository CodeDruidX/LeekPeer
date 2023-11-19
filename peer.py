from tortools import * 
import config as cfg
import requests				#pip install requests
from requests_tor import RequestsTor	#pip install requests-tor
rt = RequestsTor(tor_ports=(9050,))
import os
import re
import time

basebase=['!', '#', '$', '%', '&', '(', ')', '*', '+', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~']

betterbase=['Й', 'Ц', 'Ъ', 'Ж', 'Э', 'Н', 'Г', 'Ш', 'Щ', 'З', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'Ф', 'Ы', 'Ч', 'Ю', 'Б', 'Ь', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'ё', 'Л', 'Д', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'ц', 'я', 'Я', 'й']

t_bett={}
t_base={}
for i in range(len(basebase)):
	t_bett.update({ord(basebase[i]):betterbase[i]})
	t_base.update({ord(betterbase[i]):basebase[i]})

def b_2_b85(b:bytes):
	
	return base64.b85encode(b).decode().translate(t_bett)

def b85_2_b(s:str):

	return base64.b85decode(s.translate(t_base))

def make(bin_data:bytes):
	publickey=k.verify_key.encode()
	return b_2_b85(sign(publickey+bin_data))+b_2_b85(publickey)

def check(maked:str,data:bytes):
	try:
		sig,pub=b85_2_b(maked[:80]),b85_2_b(maked[80:120])
		VerifyKey(pub).verify(pub+data,sig)
		return True
	except:
		return False

def onion(pub):return onion_address_from_public_key(pub)

def deploy(file):
	dat=open(file,"rb").read()
	if len(os.path.basename(file).split(".",1)) == 1:
		res=""
	else:
		res=os.path.basename(file).split(".",1)[1]

	name=make(dat)+"."+res
	try: os.mkdir("storage")
	except FileExistsError: pass
	open(f"storage/{name}","wb").write(dat)

def load(name:str,data:bytes):
	if check(os.path.basename(name).split(".",1)[0],data):
		try: os.mkdir("storage")
		except FileExistsError: pass
		open(f"storage/{os.path.basename(name)}","wb").write(data)
		return True
	return False

def download(url,tor=True):
	local_filename = url.split('/')[-1]

	if len(os.path.basename(local_filename).split(".",1)) == 1:
		if not "" in cfg.allowed_res: return False
	else:
		if not os.path.basename(local_filename).split(".",1)[1] in cfg.allowed_res: return False

	b=b""
	r = (rt if tor else requests).get(url, stream=True)
	for chunk in r.iter_content(chunk_size=1024):
		if chunk: b+=chunk
		if len(b)>=cfg.max_file_kb_size*1024: return False
	#print(local_filename,b)
	return load(local_filename,b)

def catalouge(url,tor=True):
	res=(rt if tor else requests).get(url)
	res.encoding="utf-8"
	files=re.findall("<li><a.*?>(.*?)<\/a><\/li>",res.text)
	return files

def unknown(c):
	return set([i for i in c])-set(os.listdir("storage"))



def sync(url,tor=True):
	if cfg.blacklist_enabled and url in cfg.blacklist: return False
	try:
		c=catalouge(url,tor)
	except:
		print("📛 Unreachable domain",url)
		return False
	u=list(unknown(c))
	print("🔄️ Downloading",len(u),"files from",url,"with",len(c),"files")
	for i in u:
		if download(url+"/"+i,tor):
			print("✅ Loaded",i)
		else: print("⚠️ Malformed",i)


def walker(tor=True):
	urls=set()
	for i in os.listdir("storage"):
		urls.update({"http://"+onion(b85_2_b(i[80:120]))})
	for i in list(urls): sync(i,tor)


def serve():
	import subprocess as s
	s.Popen(["tor","-f","torrc"])
	s.Popen(["python","-m","http.server","8765","-d","storage"])

def cycle():
	while 1:
		time.sleep(3)
		try:
			walker()
		except Exception as e:
			print(e)

if __name__=="__main__":
	serve()
	deploy("businescard.html")
	cycle()