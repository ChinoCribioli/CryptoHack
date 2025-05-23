N = 15216583654836731327639981224133918855895948374072384050848479908982286890731769486609085918857664046075375253168955058743185664390273058074450390236774324903305663479046566232967297765731625328029814055635316002591227570271271445226094919864475407884459980489638001092788574811554149774028950310695112688723853763743238753349782508121985338746755237819373178699343135091783992299561827389745132880022259873387524273298850340648779897909381979714026837172003953221052431217940632552930880000919436507245150726543040714721553361063311954285289857582079880295199632757829525723874753306371990452491305564061051059885803
d = 11175901210643014262548222473449533091378848269490518850474399681690547281665059317155831692300453197335735728459259392366823302405685389586883670043744683993709123180805154631088513521456979317628012721881537154107239389466063136007337120599915456659758559300673444689263854921332185562706707573660658164991098457874495054854491474065039621922972671588299315846306069845169959451250821044417886630346229021305410340100401530146135418806544340908355106582089082980533651095594192031411679866134256418292249592135441145384466261279428795408721990564658703903787956958168449841491667690491585550160457893350536334242689
m = b'crypto{Immut4ble_m3ssag1ng}'

from Crypto.Util.number import bytes_to_long, long_to_bytes

def sign_message():
	from hashlib import sha256
	h = bytes.fromhex(sha256(m).hexdigest())
	from Crypto.Util.number import bytes_to_long
	signed = pow(bytes_to_long(h),d,N)
	print(signed)

##############################################################################

# We can use primefac_fork/primefac.primefac to check that n is prime:
# from primefac import primefac
# fact = primefac(171731371218065444125482536302245915415603318380280392385291836472299752747934607246477508507827284075763910264995326010251268493630501989810855418416643352631102434317900028697993224868629935657273062472544675693365930943308086634291936846505861203914449338007760990051788980485462592823446469606824421932591)
# for p in fact:
#     print(p)

n = 171731371218065444125482536302245915415603318380280392385291836472299752747934607246477508507827284075763910264995326010251268493630501989810855418416643352631102434317900028697993224868629935657273062472544675693365930943308086634291936846505861203914449338007760990051788980485462592823446469606824421932591                                                                  
e = 65537
ct = 161367550346730604451454756189028938964941280347662098798775466019463375610700074840105776873791605070092554650190486030367121011578171525759600774739890458414593857709994072516290998135846956596662071379067305011746842247628316996977338024343628757374524136260758515864509435302781735938531030576289086798942  

# # Since n is prime, phi(n) = n-1 and then we need d to satisfy d*e = 1 mod (n-1)
# d = pow(e,-1,n-1)
# pt = pow(ct,d,n)
# print(long_to_bytes(pt))

##############################################################################

def breaking_RSA_with_too_many_factors():
	n = 580642391898843192929563856870897799650883152718761762932292482252152591279871421569162037190419036435041797739880389529593674485555792234900969402019055601781662044515999210032698275981631376651117318677368742867687180140048715627160641771118040372573575479330830092989800730105573700557717146251860588802509310534792310748898504394966263819959963273509119791037525504422606634640173277598774814099540555569257179715908642917355365791447508751401889724095964924513196281345665480688029639999472649549163147599540142367575413885729653166517595719991872223011969856259344396899748662101941230745601719730556631637
	e = 65537
	ct = 320721490534624434149993723527322977960556510750628354856260732098109692581338409999983376131354918370047625150454728718467998870322344980985635149656977787964380651868131740312053755501594999166365821315043312308622388016666802478485476059625888033017198083472976011719998333985531756978678758897472845358167730221506573817798467100023754709109274265835201757369829744113233607359526441007577850111228850004361838028842815813724076511058179239339760639518034583306154826603816927757236549096339501503316601078891287408682099750164720032975016814187899399273719181407940397071512493967454225665490162619270814464

	# I factored n with sage. You run the command `sage` in a terminal and run the following in the console:
	# sage: n = 580642391898843192929563856870897799650883152718761762932292482252152591279871421569162037190419036435041797739880389529593674485555792234900969402019055601781662044515999210032698275981631376651117318677368742867687180140048715627160641771118040372573575479330830092989800730105573700557717146251860588802509310534792310748898504394966263819959963273509119791037525504422606634640173277598774814099540555569257179715908642917355365791447508751401889724095964924513196281345665480688029639999472649549163147599540142367575413885729653166517595719991872223011969856259344396899748662101941230745601719730556631637
	# sage: ecm.factor(n)

	factors_of_n = [9282105380008121879, 9303850685953812323, 9389357739583927789, 10336650220878499841, 10638241655447339831, 11282698189561966721, 11328768673634243077, 11403460639036243901, 11473665579512371723, 11492065299277279799, 11530534813954192171, 11665347949879312361, 12132158321859677597, 12834461276877415051, 12955403765595949597, 12973972336777979701, 13099895578757581201, 13572286589428162097, 14100640260554622013, 14178869592193599187, 14278240802299816541, 14523070016044624039, 14963354250199553339, 15364597561881860737, 15669758663523555763, 15824122791679574573, 15998365463074268941, 16656402470578844539, 16898740504023346457, 17138336856793050757, 17174065872156629921, 17281246625998849649]

	phiN = 1
	for p in factors_of_n:
		phiN *= p-1
	d = pow(e,-1,phiN)
	pt = pow(ct,d,n)
	print(long_to_bytes(pt))

################################################################################

def RSA_with_e_1():
	# This is the procedure given by the challenge with which the flag was encrypted. It generates two primes of 512 bits and sets d as the inverse of e in phiN.
	from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

	e = 1
	d = -1

	while d == -1:
	    p = getPrime(512)
	    q = getPrime(512)
	    phi = (p - 1) * (q - 1)
	    d = inverse(e, phi)

	n = p * q

	flag = b"XXXXXXXXXXXXXXXXXXXXXXX"
	pt = bytes_to_long(flag)
	ct = pow(pt, e, n)

	print(f"n = {n}")
	print(f"e = {e}")
	print(f"ct = {ct}")

	pt = pow(ct, d, n)
	decrypted = long_to_bytes(pt)
	assert decrypted == flag

n = 110581795715958566206600392161360212579669637391437097703685154237017351570464767725324182051199901920318211290404777259728923614917211291562555864753005179326101890427669819834642007924406862482343614488768256951616086287044725034412802176312273081322195866046098595306261781788276570920467840172004530873767                                                                  
e = 1
ct = 44981230718212183604274785925793145442655465025264554046028251311164494127485

# But encrypting with e = 1 is simply raising to the 1, which makes nothing.
# print(long_to_bytes(ct))

#################################################################################

def RSA_with_e_3():
	# Same as previous challenge but with e = 3 instead of e = 1 and with primes of 1024 bits
	from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

	e = 3
	d = -1

	while d == -1:
	    p = getPrime(1024)
	    q = getPrime(1024)
	    phi = (p - 1) * (q - 1)
	    d = inverse(e, phi) # Note: Given the explanation below, this 'inverse' call fails whenever p or q are not 2 mod 3

	n = p * q

	flag = b"XXXXXXXXXXXXXXXXXXXXXXX"
	pt = bytes_to_long(flag)
	ct = pow(pt, e, n)

	print(f"n = {n}")
	print(f"e = {e}")
	print(f"ct = {ct}")

	pt = pow(ct, d, n)
	decrypted = long_to_bytes(pt)
	assert decrypted == flag

def decrypt_when_e_is_3():
	n = 17258212916191948536348548470938004244269544560039009244721959293554822498047075403658429865201816363311805874117705688359853941515579440852166618074161313773416434156467811969628473425365608002907061241714688204565170146117869742910273064909154666642642308154422770994836108669814632309362483307560217924183202838588431342622551598499747369771295105890359290073146330677383341121242366368309126850094371525078749496850520075015636716490087482193603562501577348571256210991732071282478547626856068209192987351212490642903450263288650415552403935705444809043563866466823492258216747445926536608548665086042098252335883
	e = 3
	ct = 243251053617903760309941844835411292373350655973075480264001352919865180151222189820473358411037759381328642957324889519192337152355302808400638052620580409813222660643570085177957

	# We want to find a d such that 3*d = 1 mod phi(n). Since d < phi(n), 3*d < 3*phi(n), and 1 < 3*d trivially. Therefore, 3*d = phi(n)+1 OR 2*phi(n)+1
	# Now, we know that p and q cannot be 0 mod 3 since they are primes greater than 3.
	# Furthermore, they cannot be 1 mod 3 because in that case phi(n) would be multuple of 3, and 3 wouldn't have inverse mod phi(n).
	# Thus, p = q = 2 mod 3 and then n = phi(n) = 1 mod 3, which means that 3*d = 2*phi(n)+1.
	# Since n < 2*phi(n) < 2*n, we get that 3*d = 2*phi(n)+1-n = n-2(p+q)+3.


	# All this development was useless because, since ct = pt^3 mod phi(n), one strategy is to check if the equality holds for the integers.
	# It is easy to check if a number is a perfect cube by doing a binary search.
	# And it works for this particular case. FML.

	cbrt_n = 0
	lo = 0
	hi = ct
	while lo < hi-1:
		# print(lo,hi)
		mid = (lo+hi)//2
		cube = mid**3
		if cube == ct:
			cbrt_n = mid
			break
		if cube < ct:
			lo = mid
		else:
			hi = mid

	assert(cbrt_n**3 == ct)
	# Since we found x such that x^3 = ct in the integers, it must also be true in any modulo, so x = pt such that pt^e = ct mod phi(n)
	print(long_to_bytes(cbrt_n))

# After thinking about it, it makes sense that pt^3 = ct in the integers because
# if you look at the number of bits that represent each number, we can conclude that pt^3 < n/2 < phi(n).
# n is 2048 bits, so phi(n) will be at least 2047 bits. Now, pt being a string of < 50 bytes, it can be represented with < 8*50 = 400 bits.
# Therefore, pt^3 will be of < 1200 bits, giving pt^3 < phi(n)

# decrypt_when_e_is_3()

################################################################################

def find_smallest_generator(p):
	# Since <g> is a subgroup of F_p*, its order must be divisible by the order of F_p*, which is p-1.
	# Therefore, if it is a proper subgroup, its order must be a proper divisor of p-1.
	# Also, |<g>| is the smallest positive int r such that g^r = 1 mod p,
	# so we just have to check that g^d != 1 mod p for each d|p-1 to ensure that g is a generator.

	proper_divisors = []
	for i in range(2,int(p**.5)+1):
		if (p-1) % i == 0:
			proper_divisors.append(i)
			proper_divisors.append((p-1)//i)
	# This is not the most efficient way to compute the divisors of p-1, but it's enough for now.

	for g in range(2,p-1):
		candidate = True
		for d in proper_divisors:
			if pow(g,d,p) == 1:
				candidate = False
				break
		if candidate:
			return g

# print(find_smallest_generator(28151))

##################################################################################

g = 2
p = 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919
a = 972107443837033796245864316200458246846904598488981605856765890478853088246897345487328491037710219222038930943365848626194109830309179393018216763327572120124760140018038673999837643377590434413866611132403979547150659053897355593394492586978400044375465657296027592948349589216415363722668361328689588996541370097559090335137676411595949335857341797148926151694299575970292809805314431447043469447485957669949989090202320234337890323293401862304986599884732815

# print(pow(g,a,p))

#################################################################################

A = 70249943217595468278554541264975482909289174351516133994495821400710625291840101960595720462672604202133493023241393916394629829526272643847352371534839862030410331485087487331809285533195024369287293217083414424096866925845838641840923193480821332056735592483730921055532222505605661664236182285229504265881752580410194731633895345823963910901731715743835775619780738974844840425579683385344491015955892106904647602049559477279345982530488299847663103078045601
b = 12019233252903990344598522535774963020395770409445296724034378433497976840167805970589960962221948290951873387728102115996831454482299243226839490999713763440412177965861508773420532266484619126710566414914227560103715336696193210379850575047730388378348266180934946139100479831339835896583443691529372703954589071507717917136906770122077739814262298488662138085608736103418601750861698417340264213867753834679359191427098195887112064503104510489610448294420720
B = 518386956790041579928056815914221837599234551655144585133414727838977145777213383018096662516814302583841858901021822273505120728451788412967971809038854090670743265187138208169355155411883063541881209288967735684152473260687799664130956969450297407027926009182761627800181901721840557870828019840218548188487260441829333603432714023447029942863076979487889569452186257333512355724725941390498966546682790608125613166744820307691068563387354936732643569654017172
# assert(B == pow(g,b,p))
# print(pow(A,b,p))

#################################################################################

A = 112218739139542908880564359534373424013016249772931962692237907571990334483528877513809272625610512061159061737608547288558662879685086684299624481742865016924065000555267977830144740364467977206555914781236397216033805882207640219686011643468275165718132888489024688846101943642459655423609111976363316080620471928236879737944217503462265615774774318986375878440978819238346077908864116156831874695817477772477121232820827728424890845769152726027520772901423784
b = 197395083814907028991785772714920885908249341925650951555219049411298436217190605190824934787336279228785809783531814507661385111220639329358048196339626065676869119737979175531770768861808581110311903548567424039264485661330995221907803300824165469977099494284722831845653985392791480264712091293580274947132480402319812110462641143884577706335859190668240694680261160210609506891842793868297672619625924001403035676872189455767944077542198064499486164431451944
B = 1241972460522075344783337556660700537760331108332735677863862813666578639518899293226399921252049655031563612905395145236854443334774555982204857895716383215705498970395379526698761468932147200650513626028263449605755661189525521343142979265044068409405667549241125597387173006460145379759986272191990675988873894208956851773331039747840312455221354589910726982819203421992729738296452820365553759182547255998984882158393688119629609067647494762616719047466973581
assert(B == pow(g,b,p))
secret = pow(A,b,p)

# SOURCE

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os

FLAG = b'crypto{????????????????????????????}'


def encrypt_flag(shared_secret: int):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Encrypt flag
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))
    # Prepare data to send
    data = {}
    data['iv'] = iv.hex()
    data['encrypted_flag'] = ciphertext.hex()
    return data

# DECRYPT

def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')

# SOLVE

iv = '737561146ff8194f45290f5766ed6aba'
ciphertext = '39c99bf2f0c14678d6a5416faef954b5893c316fc3c48622ba1fd6a9fe85f3dc72a29c394cf4bc8aff6a7b21cae8e12c'

# print(decrypt_flag(secret, iv, ciphertext))

############################################################################


import socket
import json
import random

def parse_DH_response(msg, params):
	dict_as_string = msg.decode('utf-8').split('\n')[0]
	dic = json.loads(dict_as_string)
	response = []
	for param in params:
		response.append(int(dic[param],16)) # This tweak is because the hex parameters are sometimes given as "0x2ab4f..." and sometimes as "2ab4f...". So we have to strip that part sometimes.
	return response

def parameter_injection():
	HOST = "socket.cryptohack.org"
	PORT = 13371

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	    s.connect((HOST, PORT))
	    # Intercept message from Alice
	    print(s.recv(10000))
	    [p,g,A] = parse_DH_response(s.recv(10000), ['p','g','A'])
	    # Create an own key pair
	    c = random.randrange(2,p-1)
	    C = pow(g,c,p)
	    secret_with_Alice = pow(A,c,p)
	    # Send tampered message to Bob
	    res = bytes("{" + f'"p": "{hex(p)}", "g": "{hex(g)}", "A": "{hex(C)}"' + "}", 'ascii')
	    s.send(res)
	    # Intercept message from Bob
	    print(s.recv(10000))
	    [B] = parse_DH_response(s.recv(10000), ['B'])
	    secret_with_Bob = pow(B,c,p)
	    # Send tampered message to Alice
	    res = bytes("{" + f'"B": "{hex(C)}"' + "}", 'ascii')
	    s.send(res)
	    # Receive encrypted key and decrypt it
	    assert(len('Intercepted from Alice: ') == 24)
	    print(s.recv(24))
	    # flag_msg = s.recv(10000)
	    [iv, encrypted_flag] = parse_DH_response(s.recv(10000), ['iv', 'encrypted_flag'])
	    print(decrypt_flag(secret_with_Alice, hex(iv)[2:], hex(encrypted_flag)[2:]))
    
# parameter_injection()

###########################################################################

def MultipleChineseRemainderTheorem(remainders): # A list of restrictions in the form of (remainder_i, modulo_i)
	if len(remainders) == 1:
		return remainders[0]
	(r1,m1) = remainders[-1]
	(r2,m2) = remainders[-2]
	remainders = remainders[:-2]
	newmod = m1*m2
	remainders.append(( (r1*m2*pow(m2,-1,m1) + r2*m1*pow(m1,-1,m2)) % newmod , newmod))
	return MultipleChineseRemainderTheorem(remainders)

assert(MultipleChineseRemainderTheorem([(2,3), (3,4), (1,5)]) == (11,60))
assert(MultipleChineseRemainderTheorem([(2,3), (0,4)]) == (8,12))

def BabyStepGiantStep(g, A, n, order = 0): # Returns discrete logarithm of A mod n in O(sqrt(n)) space and time complexity
	# If we know the order of g (|<g>|) we can pass it as a the 'order' variable to restrict
	# the possible candidates for the exponents. If order == 0, then we treat g as a generator and
	# all the exponents from 0 to n-1 are candidates.
	if not order:
		order = n
	m = int(order**.5)+1
	babysteps = {}
	iterator = 1
	for j in range(m+1):
		babysteps[iterator] = j
		iterator *= g
		iterator %= n
	giantstep = pow(g,-m,n)
	iterator = A
	step_keys = babysteps.keys()
	for i in range(m):
		if iterator in step_keys:
			return i*m+babysteps[iterator]
		iterator *= giantstep
		iterator %= n
	return None

assert(pow(7894352216,BabyStepGiantStep(7894352216, 355407489, 604604729),604604729) == 355407489)
assert(BabyStepGiantStep(5,148,221) == 9)

def export_grade():
	HOST = "socket.cryptohack.org"
	PORT = 13379

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	    s.connect((HOST, PORT))
	    # Intercept message from Alice
	    print(s.recv(10000))
	    print(s.recv(10000)) # {supported: [...]}
	    # Respond a restricted set of options
	    response = b'{"supported": ["DH64"]}' # We send a small prime as the only option to force Bob to choose that one
	    s.send(response)
	    # Send the chosen group to Alice
	    print(s.recv(10000)) # Intercepted from Bob
	    msg = s.recv(10000)
	    msg = msg.split(b'\n')[0]
	    s.send(msg)
	    # Retrieve parameters from Alice
	    assert(len('Intercepted from Alice: ') == 24)
	    print(s.recv(24)) # Intercepted from Alice
	    msgs = s.recv(10000).split(b'\n') # We intercept the rest of the conversation
	    print(msgs)
	    [p,g,A] = parse_DH_response(msgs[0], ['p','g','A']) # The first part contains these parameters from Alice
	    # Retrieve params from Bob
	    assert(len('Intercepted from Bob: ') == 22)
	    [B] = parse_DH_response(msgs[1][22:], ['B']) # The second part contains Bob's public key
	    # Retrieve iv and flag
	    [iv,encrypted_flag] = parse_DH_response(msgs[2][24:], ['iv', 'encrypted_flag'])
	    # Break RSA with small modulo using 'baby-step giant-step' algorithm
	    # Since we forced them to choose a small p, we can factor p-1, which gives this prime powers as its factors:
	    factors = [8, 3, 293, 5417, 420233272499] # The prime factorization of p-1 is: 2^3 * 3 * 293 * 5417 * 420233272499
	    # Now, we will retrieve 'a' from g^a mod p the following way:
	    # Since phi(p) = p-1, 'a' is a remainder modulo p-1, so it can be recovered with all the remainders a mod p_i 
	    # for p_i being a factor of p-1. Thus, we can recover 'a' by knowing a mod p_i for all p_i
	    # in the 'factors' array, by using the CRT. So we want 'a mod p_i for p_i in factors'.
	    # Now, given some p_i, if q_i = (p-1)/p_i, we have that A^q_i = g^(q_i*a) = (g^q_i)^a. But now g^q_i is
	    # an element of order p_i in the group, so we can retrieve a mod p_i in O(sqrt(p_i)) by doing BSGS with
	    # g^q_i as a generator and A^q_i as our target number to perform the discrete logarithm.
	    # This is because in the equation A^q_i = (g^q_i)^a, 'a' is a remainder mod p_i since the order of g^q_i is p_i.
	    # Therefore, a Meet-in-the-middle idea such as the one in BSGS allows us to find the DL in a reasonable time.
	    # Another way to think this is that the group generated by g^q_i has order p_i, so the exact same idea from the classic BSGS works.
	    remainders = []
	    for p_i in factors:
	    	cofactor = (p-1)//p_i
	    	print(f"Performing BSGS with {p_i}.")
	    	r_i = BabyStepGiantStep(pow(g,cofactor,p),pow(A,cofactor,p),p,p_i)
	    	remainders.append((r_i,p_i))
	    a = MultipleChineseRemainderTheorem(remainders)[0]
	    assert(pow(g,a,p) == A)
	    secret = pow(B,a,p)
	    print(decrypt_flag(secret, hex(iv)[2:], hex(encrypted_flag)[2:]))

# export_grade()
