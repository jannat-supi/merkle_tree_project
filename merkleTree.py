from nacl.encoding import RawEncoder
from nacl.hash import sha256
from binascii import hexlify
from math import log, ceil, floor
from copy import deepcopy
import glob
import os
from random import randint
# importing the hashlib module
import hashlib

null_node = b''.join(b'\x00' for i in range(32))

def hash_file(file_name):
    hash_sha256 = hashlib.sha256()
    with open(file_name, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

class MerkleTree(list):
    def __init__ (self, base, levels, hashfunc = lambda data: sha256(data, encoder=RawEncoder)):
        self.levels = levels
        self.base = base
        self.hashfunc = hashfunc
        # create an appropriate number of empty nodes for each level, from root to leaves
        for i in range(0, levels):
            t = [null_node for c in range(0, base**i)]
            self.append(t)

    @classmethod
    def from_leaves (cls, leaves, base = 2, hashfunc = lambda data: sha256(data, encoder=RawEncoder)):
        while len(leaves) % base > 0:
            leaves.append(null_node)
        levels = ceil(log(len(leaves), base)) + 1
        tree = cls(base, levels, hashfunc)
        tree.fill(leaves)
        return tree

    @classmethod
    def from_messages (cls, messages, base = 2, hashfunc = lambda data: sha256(data, encoder=RawEncoder)):
        leaves = [hashfunc(messages[i]) for i in range(len(messages))]
        return cls.from_leaves(leaves, base, hashfunc)

    def calculate_tree(self):
        for i in range(len(self)-1, 0, -1):
            for j in range(0, len(self[i]), self.base):
                combined = b''.join(self[i][j:j+self.base])
                self[i-1][int(j/self.base)] = self.hashfunc(combined)

    def put(self, leaf, index):
        self[-1][index] = leaf
        self.calculate_tree()

    def fill(self, leaves):
        if len(leaves) > self.base**self.levels:
            raise BaseException('too many leaves')
        self[-1] = leaves
        self.calculate_tree()

    def print_hex(self):
        for i in range(0, len(self)):
            l = self[i][:]
            for c in range(0, len(l)):
                l[c] = hexlify(l[c])
            print(i, l)

    def prove(self, message):
        hash = self.hashfunc(message)
        print(hash)
        print(self)
        index = self[-1].index(hash)
        proof = []
        for l in range(self.levels-1, 0, -1):
            cohort = int(floor(index/self.base))
            placement = index - cohort*self.base
            round = [self[l][i] for i in range(cohort*self.base, (cohort+1)*self.base)]
            del round[placement]
            round.insert(0, placement)
            index = cohort
            proof.append(round)
        proof.append(self[0])
        return proof

    @staticmethod
    def print_hex_proof(proof):
        for i in range(0, len(proof)):
            l = proof[i][:]
            for c in range(0, len(l)):
                l[c] = hexlify(l[c]) if isinstance(l[c], bytes) else l[c]
            print(l)

    @staticmethod
    def verify(message, proof, hashfunc = lambda data: sha256(data, encoder=RawEncoder)):
        hash = hashfunc(message)
        working = deepcopy(proof)
        for i in range(len(proof)-1):
            index = proof[i][0]
            del working[i][0]
            working[i].insert(index, hash)
            hash = hashfunc(b''.join(working[i]))

        return hash == proof[-1][0]


leaves=[]
messages=[]

dirname = input("Please enter the file directory: ")
path = os.path.join(dirname,"**")
flag=0
for x in glob.glob(path, recursive=True):

    if(flag==0):
        flag=1
        continue
    mess = hash_file(x)
    fname=bytes(x, 'utf-8')
    messages.append(fname)
    message = bytes(mess, 'utf-8')
    leaves.append(message)
print("MerkleTree:")
m = MerkleTree.from_leaves(leaves) # base=2
m.print_hex()
print()

index = randint(0, len(messages)-1)
print("Proof the files ", messages[index], "(", str(hexlify(leaves[index])), ") is part of the tree:")
proof = m.prove(messages[index])
MerkleTree.print_hex_proof(proof)
print()

print("Proof verified" if MerkleTree.verify(messages[index], proof) else "Proof failed verification")



