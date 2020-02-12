#The rest of the problem explores the use of a one-time pad version of the Vigenere cipher. 
# In this scheme, the key is a stream of random numbers between 0 and 25. For example, 
# if the key is 3 19 5 ..., then the first letter of plaintext is encrypted with a shift of 3 letters, 
# the second with a shift of 19 letters, the third with a shift of 5 letters, and so on.

# b. Encrypt the plaintext sendmoremoney with the key stream 9 0 1 7 23 15 21 14 11 11 2 8 9

def encrypt():
	key = "9 0 1 7 23 15 21 14 11 11 2 8 9"
	print("Key = ", key)
	key = key.split(" ")
	key = [int(el) for el in key]
	key[0]
	plaintext = "sendmoremoney"
	print("Plaintext = ", plaintext)
	print("Converting to indices ...")

	# converting plaintext from characters to numbers
	plaintext_mat = [ord(el)-97 for el in plaintext]
	print("Numeric representation of plaintext = ", plaintext_mat)
	print("{} = {} + {}, but it's used only once".format(u'C\u1D62', u'P\u1D62', u'K\u1D62'))
	print("Encrypting ...")
	cipher = []
	for i in range(len(plaintext_mat)):
		print("Processing {}, {}={}".format(plaintext[i], u'K\u1D62', key[i]))
		
		# add plaintext and key, also print out to show the step
		res = plaintext_mat[i]+key[i]
		print("{} + {} = {} mod 26".format(plaintext_mat[i], key[i], res))
		print("        = ", res % 26)
		
		# add each set of characters after processing to the cipher list
		cipher.append(res % 26)
	return cipher

# line 37 calls the required function, encrypt()
# cipher = encrypt()
# print("Numeric representation of ciphertext = ", cipher)
# print("Ciphertext: {}".format(''.join([chr(el+97) for el in cipher])))

'''
c. Using the ciphertext produced in part (b), find a key so that the cipher text decrypts to the plaintext
cashnotneeded.
'''
def decrypt():
	ciphertext = "beokjdmsxzpmh"
	print("Ciphertext = ", ciphertext)
	plaintext = "cashnotneeded"
	print("Required plaintext = ", plaintext)
	
	# converting ciphertext and plaintext from characters to numbers
	cipher_mat = [ord(el)-97 for el in ciphertext]
	plaintext_mat = [ord(el)-97 for el in plaintext]
	print("Numeric representation of ciphertext = ", cipher_mat)
	print("Numeric representation of plaintext = ", plaintext_mat)
	print("To find the key, we simply use {} = {} - {}".format(u'P\u1D62', u'C\u1D62', u'K\u1D62'))
	print("                           or, {} = {} - {}".format(u'K\u1D62', u'C\u1D62', u'P\u1D62'))
	key = []
	for i in range(len(ciphertext)):
		# substract Pi from Ci
		res = cipher_mat[i] - plaintext_mat[i]
		print("Processing at i={},\n{} - {}\n= {} mod 26".format(
			i, cipher_mat[i], plaintext_mat[i], res))
		res = res % 26
		print("=", res)

		# add each set of characters after processing to the key list
		key.append(res)
	print("The required key is = ", ''.join([str(el)+" " for el in key]))
decrypt()