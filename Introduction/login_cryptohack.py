cipher = "XZSSD TGQNLJ XMJQQ HMJK"
l = len(cipher)
omin = ord('A')
omax = ord('Z')
d = omax-omin+1

for i in range(d):
	new_cipher = ""
	for j in range(l):
		if cipher[j] == ' ':
			new_cipher += cipher[j]
			continue
		new_ord = ord(cipher[j])+i
		if new_ord > omax:
			new_ord -= d
		new_cipher += chr(new_ord)
	print(new_cipher)