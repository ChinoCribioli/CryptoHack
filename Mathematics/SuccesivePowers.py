def isPrime(p):
	for i in range(2,int(p**0.5)+2):
		if p%i == 0:
			return False
	return True

powers = [588,665,216,113,642,4,836,114,851,492,819,237]
l = len(powers)

for p in range(853,1000,2):
	if not isPrime(p):
		continue
	candidate_x = pow(588,-1,p)*665
	candidate_x %= p
	isCandidate = True
	for i in range(len(powers)-1):
		if (pow(powers[i],-1,p)*powers[i+1])%p != candidate_x:
			isCandidate = False
			break
	if isCandidate:
		print(candidate_x, p)