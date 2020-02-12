import argparse

parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('--function', help="specify whether to encrypt or decrypt function")
parser.add_argument('--txt', help="plaintext or ciphertext")
# print(args.function)


def _encrypt(p):
	# python's ord() function returns ascii of a character
	# ord('a') = 97 and we want a to be 0. So we reduce everything by 97
	p_mat = [ord(p[0])-97, ord(p[1])-97]
	# multiply by key
	#   (9  4)
	#	(5	7)
	cipher_nums = [(p_mat[0]*9 + p_mat[1]*4) % 26, (p_mat[0]*5 + p_mat[1]*7) % 26]
	# convert back to text using python's chr() function
	return chr(cipher_nums[0]+97), chr(cipher_nums[1]+97)

# the plaintext below is stripped of the space and q is added to make it compatible
# with the given key
# p = 'meetmeattheusualplaceattenratherthaneightoclockq'

def encrypt(p):
	print("Plaintext: {}, \nlength of plaintext: {}".format(p, len(p)))
	ret = ''
	# the 2 after 48 increases the loop counter by two
	# in other words we have to take two characters for a total of 24 times 
	l = len(p)
	for i in range(0, l, 2):
		ctxt1, ctxt2 = _encrypt(p[i]+p[i+1])
		print("{} converted to {}\n{} converted to {}".format(p[i], ctxt1, p[i+1], ctxt2))
		ret += ctxt1 + ctxt2 # chr(tmp1+97)+chr(tmp2+97)
	print("Ciphertext: {}, \nlength of ciphertext: {}".format(ret, len(ret)))

# a lot of information is in the output that is attached with the rest of the howework
def calculate_inverse_matrix():
	# We 'statically' calculate the K inverse as it remains fixed throughout the computation
	print("Calculating determinant (d) = 7 * 9 - 5 * 4")
	det = 7 * 9 - 5 * 4
	print("                            = ", det)
	print("Inverse of determinant is a, such that 43 * a = 1 mod 26")
	print("which gives a = 23")
	print("Calculating conjugate of key... ")
	print("The conjugate of the key, c = ", end=' ')
	print("(7  -4)")
	print("                               (-5  9)")
	print("                            =  (7  22)")
	print("                            =  (21  9)")
	print("The inverse of the matrix, {} = 23 * c".format(u'K\u207B\u00B9'))
	print("                              = 23 * (7  22)   mod 26")
	print("                                     (21  9)")
	print("                              = (5   12)")
	print("                                (15  25)")
	return 
	
def _decrypt(c):
	# just some coloring to highlight key text in the output
	print("\033[1;30;47m Processing {}, {}\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t".format(c[0], c[1]))
	print("\033[1;32;44m")
	# same as encryption, reduce by ascii of 97
	c_mat = [ord(c[0])-97, ord(c[1])-97]
	print("{}C".format(u'K\u207B\u00B9'))
	print("= (5   12) * ({})   mod 26".format(c_mat[0]))
	print("  (15  25)   ({})".format(c_mat[1]))
	print("= ({})   mod 26".format(5*c_mat[0] + 12*c_mat[1]))
	print("  ({})".format(15*c_mat[0] + 25*c_mat[1]))
	plain_nums = [(5*c_mat[0] + 12*c_mat[1]) % 26, (15*c_mat[0] + 25*c_mat[1]) % 26]
	print("=({}) ".format(plain_nums[0]))
	print(" ({}) ".format(plain_nums[1]))
	return chr(plain_nums[0]+97), chr(plain_nums[1]+97)

def decrypt(c):
	print("Part b, decryption ...")
	print("Again, ciphertext: {}, \nlength of ciphertext: {}".format(c, len(c)))
	calculate_inverse_matrix()
	ptxt = ""
	# the 2 after 48 increases the loop counter by two
	# in other words we have to take two characters for a total of 24 times 
	l = len(c)
	for i in range(0, l, 2):
		ptxt1, ptxt2 = _decrypt(c[i]+c[i+1])
		ptxt += ptxt1 + ptxt2

	print("Plaintext with q removed: {}, \nlength of plaintext: {}".format(ptxt[:48], len(ptxt)))

if __name__ == '__main__':
	args = parser.parse_args()
	if args.function == 'encrypt':
		encrypt(args.txt)
	elif args.function == 'decrypt':
		decrypt(args.txt)
'''
	THE
		ANSWER IS 
			ukixukydromeiwszxwiokunukhxhroajroanqyebtlkjegyg
'''