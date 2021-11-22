# Author: patacca
# License: GPLv2


import sys, logging, hashlib, collections, random, time, sqlite3, json, re
import angr

from sortedcontainers import SortedKeyList
from functools import cached_property

X86_GRP_JUMP = 1
X86_GRP_BRANCH_RELATIVE = 7


def usage():
	print(f'Usage: {sys.argv[0]} file1 file2')
	exit(0)

def fnvStr(data: str) -> int:
	'''Compute the FNV-1a Hash in 64 bits flavor'''
	
	h = 0xcbf29ce484222325
	mask64 = 2**64 - 1
	for b in data:
		h ^= ord(b)
		h = (h*0x100000001b3) & mask64
	
	return h

def fnvBytes(data: bytearray) -> int:
	'''Compute the FNV-1a Hash in 64 bits flavor'''
	
	h = 0xcbf29ce484222325
	mask64 = 2**64 - 1
	for b in data:
		h ^= b
		h = (h*0x100000001b3) & mask64
	
	return h

def fastDotProduct(v1: dict, v2: dict) -> int:
	'''Fast dot product between two vectors in dict notation'''
	
	shortVec = v1
	longVec = v2
	if len(shortVec) > len(longVec):
		shortVec, longVec = longVec, shortVec
	
	return sum(shortVec[k]*longVec[k] for k in shortVec if k in longVec)

class Differ:
	def __init__(self, primary, secondary, verbosity=logging.INFO):
		# Configure logging
		handler = logging.StreamHandler()
		formatter = logging.Formatter('%(message)s')
		handler.setFormatter(formatter)
		
		self.logger = logging.Logger(__name__)
		self.logger.addHandler(handler)
		self.logger.setLevel(verbosity)
		
		# ~ logging.getLogger('angr').setLevel(verbosity)
		
		# Use sqlite3 database to save the analysis result
		self.db = sqlite3.connect('./db.sqlite3')
		
		# Parse the binaries
		self.primary = angr.Project(primary, load_options={'auto_load_libs': False}, use_sim_procedures=False)
		self.secondary = angr.Project(secondary, load_options={'auto_load_libs': False}, use_sim_procedures=False)
		
		self.primaryCFG = self.primary.analyses.CFGFast(resolve_indirect_jumps=True, normalize=True)
		self.secondaryCFG = self.secondary.analyses.CFGFast(resolve_indirect_jumps=True, normalize=True)
		
		self.primaryFunctions = {a:f for a,f in self.primaryCFG.kb.functions.items() if f.binary_name == self.primary.filename and not f.is_plt}
		self.secondaryFunctions = {a:f for a,f in self.secondaryCFG.kb.functions.items() if f.binary_name == self.secondary.filename and not f.is_plt}
		
		# Generate the hyperplanes for the LSH
		# Each hyperplane is identified by its normal vector v from R^2000: v * x = 0
		# the dimension 2000 should be sufficient to characterize the basic asm blocks
		self.hyperplanes = []
		for k in range(32):
			self.hyperplanes.append([2*random.random() - 1 for i in range(2000)])
		
		# Matching functions. addr -> match
		self.matchesPrimary = collections.defaultdict(list)
		self.matchesSecondary = collections.defaultdict(list)
		
		# Not yet matched functions
		self.unmatchedPrimary = set()
		self.unmatchedSecondary = set()
	
	def __del__(self):
		self.db.close()
	
	def debug(self, msg):
		self.logger.debug(msg)
	
	def info(self, msg):
		self.logger.info(msg)
	
	def warn(self, msg):
		self.logger.warning(msg)
	
	def error(self, msg):
		self.logger.error(msg)
	
	def log(self, msg):
		self.logger.log(100, msg)
	
	def lsh(self, block):
		'''Use a Locality Sensitive Hashing (LSH) algorithm to hash a block of code'''
		
		bag = collections.defaultdict(int)
		
		for instr in block.disassembly.insns:
			# For now only use the id
			bag[instr.id] += 1
		
		resHash = 0
		for hp in self.hyperplanes:
			resHash <<= 1
			prod = sum(hp[k]*v for k,v in bag.items())
			if prod >= 0:
				resHash |= 1
		
		return resHash
	
	def wlFeature(self, func):
		'''Calculate the Weisfeiler-Lehman feature vector for the function'''
		
		labels = []
		mapNodeToLabel = {}
		adjacency = collections.defaultdict(list)
		
		# Label each node of the graph with LSH
		for n in func.blocks:
			labels.append(self.lsh(n))
			# We have to get the BlockNode from the corresponding Block and map
			# it to our node index
			mapNodeToLabel[func.get_node(n.addr)] = len(labels)-1
		
		# Remap edges
		for edge in func.graph.edges:
			adjacency[mapNodeToLabel[edge[0]]].append(mapNodeToLabel[edge[1]])
		
		vec = [l for l in labels]
		for rep in range(len(labels)):
			# Recalculate labels
			newLabels = []
			for node,label in enumerate(labels):
				l = bin(label)
				neigh = []
				for neighbor in adjacency[node]:
					neigh.append(bin(labels[neighbor]))
				neigh.sort()
				l += ''.join(neigh)
				
				# Add 2**32 to avoid confusion with the LSH hashes
				newLabels.append(2**32 + fnvStr(l))
			
			labels = newLabels
			vec.extend([l for l in labels])
		
		# Generate the frequency vector of the labels
		return dict(collections.Counter(vec))
	
	def extractFeatures(self, source, functions):
		'''Map each function to the corresponding feature vector'''
		
		dbConn = self.db.cursor()
		dbConn.row_factory = sqlite3.Row
		dbConn.execute('SELECT * FROM functions WHERE source=?', (source,))
		dbResult = dbConn.fetchall()
		dbResult = {row['address']:row for row in dbResult}
		
		features = {}
		for addr,f in functions.items():
			if addr in dbResult:
				# Remap keys from str to int
				v = json.loads(dbResult[addr]['vector'], object_hook=lambda x: {int(k):v for k,v in x.items()})
				features[addr] = (v, dbResult[addr]['norm'])
				continue
			
			v = self.wlFeature(f)
			norm = sum(val**2 for val in v.values())
			features[addr] = (v, norm)
			dbConn.execute(
				'INSERT INTO functions (address,vector,source,name,norm) values (?,?,?,?,?)',
				(addr,json.dumps(v),source,f.name,norm)
			)
		
		self.db.commit()
		
		return features
	
	def fingerprint(self, function):
		fng = bytearray()
		
		addrs = sorted(function.block_addrs)
		for a in addrs:
			instructions = function.get_block(a).disassembly.insns
			for i in instructions:
				# Ignore relative jumps/calls
				if i.insn.group(X86_GRP_BRANCH_RELATIVE):
					fng += bytearray(int.to_bytes(i.insn.id, 2, 'little'))
					continue
				
				# Get rid of relative data discrepancies caused by the use of the rip register
				m = re.findall('\[(rip (\+|\-) .*)\]', i.op_str)
				if m != []:
					fng += bytearray(int.to_bytes(i.insn.id, 2, 'little'))
					continue
				
				fng += i.insn.bytes
		
		return fnvBytes(fng)
	
	def fingerprintMatch(self):
		'''Match functions that have the same non-relative bytes hash'''
		
		self.info('[+] Starting perfect match analysis')
		
		fingerprints1 = collections.defaultdict(list)
		for f in self.primaryFunctions.values():
			if f.size == 0:
				continue
			fingerprints1[self.fingerprint(f)].append(f)
		
		for f2 in self.secondaryFunctions.values():
			if f2.size == 0:
				continue
			fng = self.fingerprint(f2)
			if fng in fingerprints1:
				for f1 in fingerprints1[fng]:
					# This could rewrite some matches but we can safely (reasonably) ignore that
					# since that would mean there are multiple equal functions.
					# Without context analysis it is impossible to discerne between those
					self.matchesPrimary[f1.addr].append(f2)
					self.matchesSecondary[f2.addr].append(f1)
		
		for fAddr in self.primaryFunctions:
			if fAddr not in self.matchesPrimary:
				self.unmatchedPrimary.add(fAddr)
		
		for fAddr in self.secondaryFunctions:
			if fAddr not in self.matchesSecondary:
				self.unmatchedSecondary.add(fAddr)
	
	def analyze(self):
		self.log(f'[+] Analyzing files {self.primary.filename} and {self.secondary.filename}')
		
		self.fingerprintMatch()
		
		self.debug(f'[d] {len(self.matchesPrimary)} functions from {self.primary.filename} have been matched')
		self.debug(f'[d] {len(self.matchesSecondary)} functions from {self.secondary.filename} have been matched')
		self.debug(f'[d] {len(self.unmatchedPrimary)} functions from {self.primary.filename} are still unmatched')
		self.debug(f'[d] {len(self.unmatchedSecondary)} functions from {self.secondary.filename} are still unmatched')
		
		# ~ cont = 0
		# ~ for fAddr1,f2 in self.matchesPrimary.items():
			# ~ f1 = self.primaryFunctions[fAddr1]
			# ~ l = set((f.name for f in f2))
			# ~ if f1.name not in l:
				# ~ print('ERROR', f1.name, f2)
				# ~ continue
			# ~ if len(l) > 1:
				# ~ print(f1.name, len(f2))
				# ~ cont += 1
		
		# ~ print(cont)
		
		primaryFunctions = {fAddr:self.primaryFunctions[fAddr] for fAddr in self.unmatchedPrimary}
		secondaryFunctions = {fAddr:self.secondaryFunctions[fAddr] for fAddr in self.unmatchedSecondary}
		
		start = time.time()
		primaryFunctionsFeatures = self.extractFeatures(self.primary.filename, primaryFunctions)
		self.info(f'[+] {len(primaryFunctionsFeatures)} functions analyzed in {(time.time()-start):.4f} seconds')
		
		start = time.time()
		secondaryFunctionsFeatures = self.extractFeatures(self.secondary.filename, secondaryFunctions)
		self.info(f'[+] {len(secondaryFunctionsFeatures)} functions analyzed in {(time.time()-start):.4f} seconds')
		
		start = time.time()
		matches = {'primary' : {}, 'secondary' : collections.defaultdict(list)}
		# ~ perfectMatches = {'primary' : {}, 'secondary' : collections.defaultdict(list)}
		unmatchedFunctions = {'primary' : set(), 'secondary' : set()}
		for addr1,(vec1,norm1) in primaryFunctionsFeatures.items():
			matches['primary'][addr1] = []
			# ~ perfectMatches['primary'][addr1] = []
			for addr2,(vec2,norm2) in secondaryFunctionsFeatures.items():
				prod = fastDotProduct(vec1, vec2)
				norm = (norm1*norm2)**0.5
				matches['primary'][addr1].append((prod/norm, addr2))
				matches['secondary'][addr2].append((prod/norm, addr1))
				# ~ if prod == norm:
					# ~ perfectMatches['primary'][addr1].append(addr2)
					# ~ perfectMatches['secondary'][addr2].append(addr1)
			
			# Sort by the matching score
			matches['primary'][addr1].sort(key=lambda x: -x[0])
			
			if matches['primary'][addr1][0][0] < 0.2:
				unmatchedFunctions['primary'].add(addr1)
		
		for addr in secondaryFunctionsFeatures:
			matches['secondary'][addr].sort(key=lambda x: -x[0])
			if matches['secondary'][addr][0][0] < 0.2:
				unmatchedFunctions['secondary'].add(addr)
			# ~ if len(perfectMatches['secondary'][addr]) == 0:
				# ~ unmatchedFunctions['secondary'].add(addr)
				# ~ # Sort only when there isn't a perfect match
				# ~ matches['secondary'][addr].sort(key=lambda x: -x[0])
		
		self.info(f'[+] CFG matching completed in {(time.time()-start):.4f} seconds')
		self.log('\n-- REPORT --\n')
		self.log(f'{len(matches["primary"])-len(unmatchedFunctions["primary"])} functions from {self.primary.filename} have a perfect match in {self.secondary.filename}')
		self.log(f'{len(matches["secondary"])-len(unmatchedFunctions["secondary"])} functions from {self.secondary.filename} have a perfect match in {self.primary.filename}')
		
		print([self.primaryCFG.functions[f].name for f in unmatchedFunctions['primary']])
		
		for addr1 in unmatchedFunctions['primary']:
			print(f'{self.primaryCFG.functions[addr1].name}')
			print(matches['primary'][addr1][:5])

def main():
	differ = Differ(sys.argv[1], sys.argv[2], verbosity=logging.DEBUG)
	# ~ differ = Differ(sys.argv[1], sys.argv[2])
	differ.analyze()


if __name__ == '__main__':
	if len(sys.argv) != 3:
		usage()
	
	main()
