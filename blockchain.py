import json
import hashlib
from time import time
import sys
import socket
import random
import binascii

def jsonDumper(block):
	sorted_block="{"
	sorted_keys=sorted(block.keys())
	for key in sorted_keys:
		if(key=="transactions"):
			print("!!")
			print(type(block[key]))
		if type(block[key])==str:
			sorted_block+="\""+key+"\": \""+block[key]+"\", "
		elif type(block[key])==int or type(block[key])==float :
			sorted_block+="\""+key+"\": "+str(block[key])+", "
		elif type(block[key])==list:
			sorted_block+="\""+key+"\": ["    
			for i in block[key][:-1]:
				sorted_block+=jsonDumper(i)+", "
			if len(block[key])>0:
				sorted_block+=jsonDumper(block[key][-1])
			sorted_block+="], "
		else:
			print("|||||||||||||||||||")
			print(type(block[key]))
	sorted_block=sorted_block[:-2]+"}"
	return sorted_block

	
def urlparse(ali):
	res={}
	res['scheme']=ali[:ali.find("://")]
	nex_=ali.find("/",ali.find("/")+2)
	if nex_==-1:
		res['netloc']=ali[ali.find("://")+3:] 
		res['path']="" 
	else:
		res['netloc']=ali[ali.find("://")+3:nex_] 
		res['path']=ali[nex_:] 
	return res

try:
	import os
	OS_TYPE=os.uname()[0]
except:
	import platform
	OS_TYPE=platform.uname()[0]
if(OS_TYPE=="Linux" or OS_TYPE=="Windows"):
	from urllib.parse import urlparse
	from flask import Flask,jsonify,request
	import ifaddr
	from uuid import uuid4
	import requests
	from uuid import getnode as get_mac 
elif(OS_TYPE=="esp32"):
	import picoweb
	import machine
	import network
	import urequests as requests
else:
	print("You OS is not supported!")

def hexShow(input):
	if(input>9):
		return chr(input+87)
	else:
		return chr(input+48)


def getIps():
	res={}
	if(OS_TYPE=="esp32"):
		res["ap"]=ap.ifconfig()[0]
		res["mynet"]=mynet.ifconfig()[0]
		res["lo"]="127.0.0.1"
	else:
		adapters = ifaddr.get_adapters()
		for adapter in adapters:
			i=0
			for ip in adapter.ips:
				res[adapter.nice_name+str(i)]=ip.ip  
				i+=1  
	return res


class Blockchain():
	#defines a blockchain on one machine
	def __init__(self):
		self.chain=[]
		self.current_transactions=[]
		self.node=set()
		#Create the genesis block
		self.new_block(previous_hash=1, proof=100)

	def new_block(self, proof, previous_hash=None):
			#Create a new Block in the Blockchain
			#proof: The proof given by the Proof of Work algorithm
			#previous_hash: Hash of previous Block
			#returns New Block
		block={
						'index':len(self.chain)+1,
						'timestamp':int(time()),
						'transactions':self.current_transactions,
						'proof': proof,
						'previous_hash': previous_hash or self.hash(self.chain[-1]),

		}
		#Reset the current list of transactions
		self.current_transactions=[]
		self.chain.append(block)

		return block

	def new_transaction(self, sender, recipient, amount):
		#create a new transaction to go into the next mined block
		#returns the index of the block that will hold this transaction
		self.current_transactions.append({'sender':sender,'recipient':recipient,
				'amount':amount,"transaction_time":int(time())})
		return self.last_block['index']+1

	@staticmethod
	def hash(block):
		#hash a block
		try:
			block_string= json.dumps(block,sort_keys=True).encode()
		except:
			block_string=jsonDumper(block)
		#print(block_string)
		res=""
		try:
			res=hashlib.sha256(block_string).hexdigest().decode()
		except:
			res=binascii.hexlify(hashlib.sha256(block_string).digest()).decode()
		return res

	def register_node(self, address):
		#Add a new node to the list of nodes
		parsedURL=urlparse(address)
		try:
			self.node.add(parsedURL.netloc)
		except:
			self.node.add(parsedURL['netloc'])

	def valid_chain(self, chain):
		#Check if a given blockchain is valid
		last_block=chain[0]
		current_index=1
		while current_index <len(chain):
			block=chain[current_index]
			if block['previous_hash'] != self.hash(last_block):
				print("!!")
				return False
			if not self.valid_proof(block,block['proof']):
				print("##")
				print(block)
				print(self.hash(block))
				return False
			
			last_block=block
			current_index+= 1
		return True

	def resolveConflicts(self):
		#consensus algorithm, checks best chain
		#returns True if our chain was replaced, False if not
		neighbours=self.node
		new_chain=None
		max_length=len(self.chain)
		for node in neighbours:
			print(node)
			try:
				response=requests.get('http://{}/chain'.format(node))
				if response.status_code ==200:
					length= response.json()['length']
					chain=response.json()['chain']
					if length>max_length and self.valid_chain(chain):
						max_length=length
						new_chain=chain
			except:
				print("Error: node {} is unreachable!".format(node))

		if new_chain:
			self.chain = new_chain
			return True

		return False
	
	def setBlockProof(self, index, proof):
		self.chain[index]['proof']=proof

	@property
	def last_block(self):
		#return last block
		return self.chain[-1]

	@staticmethod
	def valid_proof(block, proof):
		#checks wheter nonce is as expected
		blockUT=block
		blockUT['proof']=proof
		#this_proof = "{}{}".format(proof,last_proof).encode()
		#try:
		#    this_proof_hash=hashlib.sha256(this_proof).hexdigest()
		#except:
		#    this_proof_hash = binascii.hexlify(hashlib.sha256(this_proof).digest()).decode()
		hashVal=Blockchain.hash(blockUT)
		return hashVal[:2]=='00'
		
	def proof_of_work(self, block):
		#proof of work algorithm
		proof=0
		while self.valid_proof(block,proof) is False:
			proof +=1

		return proof

#instantiate the Node
if(OS_TYPE=="Linux" or OS_TYPE=="Windows"):
	app = Flask(__name__)
else:
	app = picoweb.WebApp(__name__)

#create node id
#node_id = str(uuid4())
try:
	mac_int=get_mac()
except:
	mac_ar=network.WLAN().config('mac')
	mac = binascii.hexlify(mac_ar,':').decode()
	mac_int=0
	for i in mac_ar[:-1]:
			mac_int+=i
			mac_int*=256
	mac_int+=mac_ar[-1]
random.seed(mac_int)
node_id =""
for i in range(32):
	node_id+=hexShow(random.getrandbits(4))
	if i==7 or i==11 or i == 15 or i== 19:
		node_id+="-"
#node_id=binascii.hexlify(node_id).decode()
print("node_id is: %s" % node_id)

#instantiate the Blockchain
blockchain = Blockchain()

if(OS_TYPE!="esp32"):
	@app.route('/mine')
	def mineHandler():
		res,code=mine()
		return jsonify(res),code
	@app.route('/transactions/new',methods=['POST'])
	def new_transactionHandler():
		values=request.get_json()
		res,code= new_transation(values)
		return jsonify(res),code
	@app.route('/chain')
	def full_chainHandler():
		res,code= full_chain()
		return jsonify(res),code

	@app.route('/nodes/register',methods=['POST'])
	def register_nodeHanler():
		values=request.get_json()
		res,code=register_node(values)
		return jsonify(res),code

	@app.route('/nodes/resolve')
	def consensusHandler():
		res,code = consensus()
		return jsonify(res),code
else:
	@app.route('/mine')
	def mineHandler(req,resp):
		res,code=mine()
		yield from picoweb.jsonify(resp,res)

	@app.route('/transactions/new')
	def new_transactionHandler(req,resp):
		if req.method!= "POST":
			req.parse_qs()
			yield from picoweb.http_error(resp, "500")
		else:
			yield from req.read_form_data()
			dt=""
			for i in req.form:
				dt+=str(i)
			values=json.loads(dt)
			res,code=new_transaction(values)
			yield from picoweb.jsonify(resp,res)
	
	@app.route('/chain')
	def full_chainHandler(req, resp):
		res,code=full_chain()
		yield from picoweb.jsonify(resp,res)

	@app.route('/nodes/register')
	def register_nodeHanler(req, resp):
		if req.method!= "POST":
			req.parse_qs()
			yield from picoweb.http_error(resp, "500")
		else:
			yield from req.read_form_data()
			dt=""
			for i in req.form:
					dt+=str(i)
			values=json.loads(dt)
			res,code=register_node(values)
			yield from picoweb.jsonify(resp,res)

	@app.route('/nodes/resolve')
	def consensusHandler(req, resp):
		res,code=consensus()
		yield from picoweb.jsonify(resp,res)


def mine():
	#this will mine and add to the chain
	last_block=blockchain.last_block
	#last_proof=last_block['proof']
	#we must receive a reward for finding the proof.
	#the sender is "0" to signify that this node has mined a new coin.
	index=blockchain.new_transacion(sender="0", recipient=node_id, amount=1)
	proof=0
	#forge the new Block by adding it to the chain
	previous_hash=blockchain.hash(last_block)
	block=blockchain.new_block(proof,previous_hash)

	proof=blockchain.proof_of_work(block)
	blockchain.setBlockProof(index-1, proof)
	
	res={
		"messege":"new block created",
		"index":block['index'],
		"transactions": block['transactions'],
		"proof":block['proof'],
		"previous_hash":block['previous_hash']
	}
	return res, 200

def new_transaction(values):
	#add a new transaction
	this_blockIndex = blockchain.new_transaction(values['sender'],values['recipient'],values['amount'])
	res={
			'messege'  : 'will be added to block {}'.format(this_blockIndex)
	}
	return  res, 201

def full_chain():
	#get full chain
	res={
			'chain': blockchain.chain,
			'length':len(blockchain.chain),
	}
	return res, 200

def register_node(values):
	#register new node to blockchain network
	nodes=values.get('nodes')
	myaddrs=[]
	ips=getIps()
	for ip in ips:
		global port
		myaddrs.append("http://"+str(ips[ip])+":"+str(port))
	for node in nodes:
		node=node.replace("localhost","127.0.0.1")
		duplicate=0
		for ip in myaddrs:
			if(node==ip):
				duplicate=1
		if not duplicate:
			blockchain.register_node(node)
			print("%s added!" % node)
		else:
			print("Duplicated ip address!")

	res={
			"messege":"node added!",
			"total nodes:":list(blockchain.node)
	}
	return res, 201


def consensus():
	#decide which blockchain to use (the best)
	replaced=blockchain.resolveConflicts()
	if replaced:
		res={
				"messeges": "replaced!"
				,"new chain": blockchain.chain
		}
	else:
		res={
				"messeges": "I am already the best"
				,"chain": blockchain.chain
		}
	return res, 200

if __name__ == "__main__":
	global port
	port =80
	if len(sys.argv)>1:
			port=int(sys.argv[1])
	print("available addresses:")
	ips=getIps()
	for i in ips:
			if type(ips[i])==str:
					print(ips[i]+":"+str(port))
	if(OS_TYPE=="esp32"):
		try:
			app.run(debug=True, host = "0.0.0.0", port=port)
		except:
			gc.collect()
			machine.soft_reset()
		finally:
			print("bye!")
	else:
		app.run(host="0.0.0.0", port=port)