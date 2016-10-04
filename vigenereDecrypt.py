#!/usr/bin/env python
import sys
import time
import argparse
import os

# Argument Parser for arguments -l -k -m -f
parser = argparse.ArgumentParser(description = 'Performs Vigenere decryption', usage = 'Usage: ./vigenereDecrypt.py -f filename [-l keyLength] [-k key] [-m maxKeyLength]', prog = 'vigenereDecrypt.py')

parser.add_argument('-f', '--filename', dest = 'fileName', required = True, help = 'name of the file which contains encrypted text')

parser.add_argument('-l', '--keyLength', dest = 'keyLength', type = int, help = "length of the encryption key", default = 0)

parser.add_argument('-k', '--key', dest = 'key', help = "the key to be used in decryption", default = "")

parser.add_argument('-m', '--maxKeyLength', dest = 'maxKeyLength', help = "maximum key length to be used during decryption", type = int, default = 30)

args = parser.parse_args()


alphabet = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074]

letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

def shift(seq, n):
	return seq[len(seq) - n: ] + seq[:len(seq) - n]

def generateFrequencyList(strin):
	freq = []
	for letter in "abcdefghijklmnopqrstuvwxyz":
		freq.append(strin.count(letter))
	return [float(o)/sum(freq) for o in freq]

####################################################################################
def determineKeyLength(text):
	print("Determining key length...")
	time.sleep(1.2)
	occurences = []
	
	# determining # of coincidences by sliding text
	for i in range(1, len(text)):
		total = 0
		for a in range(0, (len(text) - i)):
			if(text[a + i] == text[a]):
				total = total + 1
		occurences.append(total)
	
	# determining key length by looking at coincidence array
	keys = []
	keyOffsets = []
	for i in range(1, maxKeyLength + 1):
		keyArray = []
		for j in range(0, i): # (offset) possibilities of starting position
			a = 0
			total = 0
			while((j + a*i) < len(occurences)):
				total = total + occurences[j + a*i]
				a = a + 1
			keyArray.append(total/a)
		keyOffsets.append(keyArray.index(max(keyArray)))
		keys.append(max(keyArray))

	# Printing key length and its possibility
	print("Key Length\tProbability")
	for i in range(1, maxKeyLength + 1):
		print(str(i) + "\t\t" + str(100.0*keys[i - 1]/sum(keys)))
		time.sleep(0.3)
	keyLength = keys.index(max(keys)) + 1
	print("")
	print("Based on above results, key length is: " + str(keyLength))
	print("NOTE: If this gives incorrect results:")
	print("\t* you may use a different key length which has a high probability.")
	print("\t* you may decrease or increase maxKeyLength parameter")
	print("NOTE: Generally if key length is small, for example 7, probability for key lengths of 14, 21, 28 will be larger. Therefore, if you identify such a situation please try with -l parameter.")
	time.sleep(1.2)

	return keyLength
######################################################################################

def determineKey(keyLength, text):
	# divide text based on key length
	dividedText = []
	for i in range(0, keyLength):
		dividedText.append(text[i:len(text):keyLength])

	# number of shifts for each key digit		
	numbers = []
	for i in range(0, len(dividedText)):
		shifts = []
		textFreq = generateFrequencyList(dividedText[i])
		for j in range(0, 26):
			newList = shift(alphabet, j)
			temp = [newList[x] * textFreq[x] for x in range(0, 26)]
			shifts.append(sum(temp))
		numbers.append(shifts.index(max(shifts)))
	print("")
	print("Key is: ")
	time.sleep(3)
	for i in numbers:
		time.sleep(0.3)
		print(letters[i]),
		sys.stdout.flush()
	
	print("")
	return numbers

########################################################################################

def decrypt(numbers, text):
	numbers = [26 - x for x in numbers]
	
	decryptedText = ""
	
	for i in range(0, len(text)):
		index = ord(text[i]) + numbers[i%keyLength];
		
		if(index > 122):
			index = index - 26
		decryptedText = decryptedText + chr(index)
	return decryptedText

########################################################################################

def addNonletterChars(decryptedText, originalText):
	for i in range(0, len(originalText)):
		if(ord(originalText[i]) < 91 and ord(originalText[i]) > 64):
			decryptedText = decryptedText[:i] + decryptedText[i].upper() + decryptedText[(i + 1):]
		elif(ord(originalText[i]) < 97 or ord(originalText[i]) > 122):
			decryptedText = decryptedText[:i] + originalText[i] + decryptedText[i:]
	return decryptedText

########################################################################################
# Arguments taken
key = args.key
maxKeyLength = args.maxKeyLength
keyLength = args.keyLength
fileName = args.fileName


if(key != ""):
	keyLength = len(key)

# Print information about execution
print("Encrypted text will be read from " + fileName)
time.sleep(0.4)
if(key != ""):
	print("Decryption will be done using the key: " + key)
else:
	if(keyLength != 0):
		print("Only keys that are " + str(keyLength) + " characters long will be used..")
	if(maxKeyLength != 30):
		print("Decryption will be done using maximum key length of " + str(maxKeyLength))

if(not os.path.isfile(fileName)):
	print(str(fileName) + " does not exists on the system.")
	sys.exit()
		
# Reading encrypted text from file
with open(fileName) as f:
	originalText = f.readlines()
originalText = originalText[0]
print("Encrypted text is read from the file as follows:")
time.sleep(1.3)
print("")
print(originalText)

# Removing non-letter characters
text = originalText
i = 0
while(i < len(text)):
	if(ord(text[i]) < 91 and ord(text[i]) > 64):
		text = text[:i] + text[i].lower() + text[(i + 1):]
	elif(ord(text[i]) < 97 or ord(text[i]) > 122):
		text = text.replace(text[i], "")
		i = i - 1
	i  = i + 1


# Check if key is provided or not
numbers = []
decryptedText = ""
if(key == ""):
	if(keyLength == 0):  # check if key length is specified or not
		keyLength = determineKeyLength(text)
		numbers = determineKey(keyLength, text)			
	else: # in case key is not known but key length is known
		numbers = determineKey(keyLength, text)
	decryptedText = decrypt(numbers, text)
else:
	numbers = []
	for letter in key:
		numbers.append(letters.index(letter))
	decryptedText = decrypt(numbers, text)
result = addNonletterChars(decryptedText, originalText)	
print("")
print("Decrypted text is as follows...")
time.sleep(1.3)
print("")
print(result)
