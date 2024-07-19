def gcd(a,b):
	if b > a:
		return gcd(b,a)
	if b == 0:
		return a
	return gcd(b,a%b)

assert(gcd(66528,52920) == 1512)

def AuxEEA(r0,s0,t0,r1,s1,t1):
	if r1 == 0:
		return (r0,s0,t0)
	q = r0//r1
	return AuxEEA(r1,s1,t1,r0-q*r1,s0-q*s1,t0-q*t1)

def extendedEucldeanAlgorithm(a,b):
	if b > a:
		unordered = AuxEEA(b,1,0,a,0,1)
		return (unordered[0], unordered[2], unordered[1])
	return AuxEEA(a,1,0,b,0,1)

(a,b) = (26513,32321)
# (1, -8404, 10245)
EEA = extendedEucldeanAlgorithm(a,b)
assert(EEA[0] == EEA[1]*a+EEA[2]*b)
EEA = extendedEucldeanAlgorithm(b,a)
assert(EEA[0] == EEA[1]*b+EEA[2]*a)

p = 101524035174539890485408575671085261788758965189060164484385690801466167356667036677932998889725476582421738788500738738503134356158197247473850273565349249573867251280253564698939768700489401960767007716413932851838937641880157263936985954881657889497583485535527613578457628399173971810541670838543309159139
exponent = (p-1)//2
ints = [25081841204695904475894082974192007718642931811040324543182130088804239047149283334700530600468528298920930150221871666297194395061462592781551275161695411167049544771049769000895119729307495913024360169904315078028798025169985966732789207320203861858234048872508633514498384390497048416012928086480326832803, 45471765180330439060504647480621449634904192839383897212809808339619841633826534856109999027962620381874878086991125854247108359699799913776917227058286090426484548349388138935504299609200377899052716663351188664096302672712078508601311725863678223874157861163196340391008634419348573975841578359355931590555, 17364140182001694956465593533200623738590196990236340894554145562517924989208719245429557645254953527658049246737589538280332010533027062477684237933221198639948938784244510469138826808187365678322547992099715229218615475923754896960363138890331502811292427146595752813297603265829581292183917027983351121325, 14388109104985808487337749876058284426747816961971581447380608277949200244660381570568531129775053684256071819837294436069133592772543582735985855506250660938574234958754211349215293281645205354069970790155237033436065434572020652955666855773232074749487007626050323967496732359278657193580493324467258802863, 4379499308310772821004090447650785095356643590411706358119239166662089428685562719233435615196994728767593223519226235062647670077854687031681041462632566890129595506430188602238753450337691441293042716909901692570971955078924699306873191983953501093343423248482960643055943413031768521782634679536276233318, 85256449776780591202928235662805033201684571648990042997557084658000067050672130152734911919581661523957075992761662315262685030115255938352540032297113615687815976039390537716707854569980516690246592112936796917504034711418465442893323439490171095447109457355598873230115172636184525449905022174536414781771, 50576597458517451578431293746926099486388286246142012476814190030935689430726042810458344828563913001012415702876199708216875020997112089693759638454900092580746638631062117961876611545851157613835724635005253792316142379239047654392970415343694657580353333217547079551304961116837545648785312490665576832987, 96868738830341112368094632337476840272563704408573054404213766500407517251810212494515862176356916912627172280446141202661640191237336568731069327906100896178776245311689857997012187599140875912026589672629935267844696976980890380730867520071059572350667913710344648377601017758188404474812654737363275994871, 4881261656846638800623549662943393234361061827128610120046315649707078244180313661063004390750821317096754282796876479695558644108492317407662131441224257537276274962372021273583478509416358764706098471849536036184924640593888902859441388472856822541452041181244337124767666161645827145408781917658423571721, 18237936726367556664171427575475596460727369368246286138804284742124256700367133250078608537129877968287885457417957868580553371999414227484737603688992620953200143688061024092623556471053006464123205133894607923801371986027458274343737860395496260538663183193877539815179246700525865152165600985105257601565]

for x in ints:
	if pow(x,exponent,p) == 1:
		(g,s,t) = extendedEucldeanAlgorithm(exponent,2)
		# Since p%4 == 3, 2 and exponent are coprime, so 1 = s*exponent + t*2, and therefore r = r^{s*exp+t*2}.
		# Since r^2 is x and r^exp is either 1 or -1, we can retrieve r by doing x^t*(±1)^s
		assert(g == 1)
		candidates = []
		for i in [1,-1]:
			candidates.append(pow(x,t,p)*pow(i,s,p)%p)
		# for c in candidates:
		# 	print(c)
# Fun fact: Since s is odd, raising to the s power does nothing to ±1, and thus the candidates are [r,-r], which are the solutions to y^2 = x (mod p). Notice that one of them is a quadratic residue and the other is not. This is because -1 is never a quadratic residue when the modulo is 3 mod 4.
# A more direct to solve this is simpy considering ±x^{(p+1)/4} since this number squared is x^{(p+1)/2} = x^{(p-1)/2+1} = x*x^{(p-1)/2} = x since x is a qr, so x^{(p-1)/2} = 1. Source: https://crypto.stackexchange.com/questions/20993/significance-of-3mod4-in-squares-and-square-roots-mod-n/20994#20994

#######################################################################

a = 8479994658316772151941616510097127087554541274812435112009425778595495359700244470400642403747058566807127814165396640215844192327900454116257979487432016769329970767046735091249898678088061634796559556704959846424131820416048436501387617211770124292793308079214153179977624440438616958575058361193975686620046439877308339989295604537867493683872778843921771307305602776398786978353866231661453376056771972069776398999013769588936194859344941268223184197231368887060609212875507518936172060702209557124430477137421847130682601666968691651447236917018634902407704797328509461854842432015009878011354022108661461024768
p = 30531851861994333252675935111487950694414332763909083514133769861350960895076504687261369815735742549428789138300843082086550059082835141454526618160634109969195486322015775943030060449557090064811940139431735209185996454739163555910726493597222646855506445602953689527405362207926990442391705014604777038685880527537489845359101552442292804398472642356609304810680731556542002301547846635101455995732584071355903010856718680732337369128498655255277003643669031694516851390505923416710601212618443109844041514942401969629158975457079026906304328749039997262960301209158175920051890620947063936347307238412281568760161

from random import randint
import copy

def Tonelli_Shanks(a,p): # Finds r such that r^2 = a (mod p)
	if a%p == 0:
		return 0
	exp = (p-1)//2
	# First, write p-1 = q*2^s
	q = p-1
	s = 0
	while q%2 == 0:
		q //= 2
		s += 1
	# Then, find a quadratic non-residue
	b = randint(2,p)
	while pow(b,exp,p) != p-1:
		b = randint(2,p)
	
	r = pow(a,(q+1)//2,p)
	t = pow(a,q,p)
	# These variables satisfy r^2 = a*t
	bq = pow(b,q,p)
	m = copy.copy(s)
	while t != 1:
		index = 0 # This will be the greatest k such that t^2^k != 1, that we know it will be equal to -1
		for i in range(m,0,-1):
			if pow(t,2**i,p) == p-1:
				index = i
				break
		m = copy.copy(index)
		new_factor = pow(bq,2**(s-2-index),p)
		t *= new_factor**2
		t %= p
		# Now, new_t^2^index = prev_t^2^index * new_factor^2^{index+1} = (-1)*(-1) = 1.
		# But we have to adjust r to keep the equality r^2 = a*t
		r *= new_factor
		r %= p
	return r

# print(Tonelli_Shanks(4,13))
r = Tonelli_Shanks(a,p)
assert(pow(r,2,p) == a)

#####################################################

for i in range(935):
	if i%5==2 and i%11==3 and i%17==5:
		# print(i)
		continue

######################################################

# ADRIEN'S SIGNS

a = 288260533169915
p = 1007621497415251

# The method to encrypt the flag was the following:
FLAG = b'crypto{????????????????????}'

def encrypt_flag(flag):
    ciphertext = []
    plaintext = ''.join([bin(i)[2:].zfill(8) for i in flag])
    for b in plaintext:
        e = randint(1, p)
        n = pow(a, e, p)
        if b == '1':
            ciphertext.append(n)
        else:
            n = -n % p
            ciphertext.append(n)
    return ciphertext

# print(encrypt_flag(FLAG)) # Gave the following ciphertext
ciphertext = [67594220461269, 501237540280788, 718316769824518, 296304224247167, 48290626940198, 30829701196032, 521453693392074, 840985324383794, 770420008897119, 745131486581197, 729163531979577, 334563813238599, 289746215495432, 538664937794468, 894085795317163, 983410189487558, 863330928724430, 996272871140947, 352175210511707, 306237700811584, 631393408838583, 589243747914057, 538776819034934, 365364592128161, 454970171810424, 986711310037393, 657756453404881, 388329936724352, 90991447679370, 714742162831112, 62293519842555, 653941126489711, 448552658212336, 970169071154259, 339472870407614, 406225588145372, 205721593331090, 926225022409823, 904451547059845, 789074084078342, 886420071481685, 796827329208633, 433047156347276, 21271315846750, 719248860593631, 534059295222748, 879864647580512, 918055794962142, 635545050939893, 319549343320339, 93008646178282, 926080110625306, 385476640825005, 483740420173050, 866208659796189, 883359067574584, 913405110264883, 898864873510337, 208598541987988, 23412800024088, 911541450703474, 57446699305445, 513296484586451, 180356843554043, 756391301483653, 823695939808936, 452898981558365, 383286682802447, 381394258915860, 385482809649632, 357950424436020, 212891024562585, 906036654538589, 706766032862393, 500658491083279, 134746243085697, 240386541491998, 850341345692155, 826490944132718, 329513332018620, 41046816597282, 396581286424992, 488863267297267, 92023040998362, 529684488438507, 925328511390026, 524897846090435, 413156582909097, 840524616502482, 325719016994120, 402494835113608, 145033960690364, 43932113323388, 683561775499473, 434510534220939, 92584300328516, 763767269974656, 289837041593468, 11468527450938, 628247946152943, 8844724571683, 813851806959975, 72001988637120, 875394575395153, 70667866716476, 75304931994100, 226809172374264, 767059176444181, 45462007920789, 472607315695803, 325973946551448, 64200767729194, 534886246409921, 950408390792175, 492288777130394, 226746605380806, 944479111810431, 776057001143579, 658971626589122, 231918349590349, 699710172246548, 122457405264610, 643115611310737, 999072890586878, 203230862786955, 348112034218733, 240143417330886, 927148962961842, 661569511006072, 190334725550806, 763365444730995, 516228913786395, 846501182194443, 741210200995504, 511935604454925, 687689993302203, 631038090127480, 961606522916414, 138550017953034, 932105540686829, 215285284639233, 772628158955819, 496858298527292, 730971468815108, 896733219370353, 967083685727881, 607660822695530, 650953466617730, 133773994258132, 623283311953090, 436380836970128, 237114930094468, 115451711811481, 674593269112948, 140400921371770, 659335660634071, 536749311958781, 854645598266824, 303305169095255, 91430489108219, 573739385205188, 400604977158702, 728593782212529, 807432219147040, 893541884126828, 183964371201281, 422680633277230, 218817645778789, 313025293025224, 657253930848472, 747562211812373, 83456701182914, 470417289614736, 641146659305859, 468130225316006, 46960547227850, 875638267674897, 662661765336441, 186533085001285, 743250648436106, 451414956181714, 527954145201673, 922589993405001, 242119479617901, 865476357142231, 988987578447349, 430198555146088, 477890180119931, 844464003254807, 503374203275928, 775374254241792, 346653210679737, 789242808338116, 48503976498612, 604300186163323, 475930096252359, 860836853339514, 994513691290102, 591343659366796, 944852018048514, 82396968629164, 152776642436549, 916070996204621, 305574094667054, 981194179562189, 126174175810273, 55636640522694, 44670495393401, 74724541586529, 988608465654705, 870533906709633, 374564052429787, 486493568142979, 469485372072295, 221153171135022, 289713227465073, 952450431038075, 107298466441025, 938262809228861, 253919870663003, 835790485199226, 655456538877798, 595464842927075, 191621819564547]

# print(FLAG[0],bin(FLAG[0]), bin(FLAG[0])[2:].zfill(5))
# plaintext = ''.join([bin(i)[2:].zfill(8) for i in FLAG[0:1]])
# print(plaintext)

# Since p%4 == 3, we know that exactly one of (n,-n) is QR modulo p. This leaves us with two possible mappings for the plaintext:
# (a): if n is a QR, we had a 1 in the plaintext. And if n is not, we had a 0.
# (b): if n is a QR, we had a 0 in the plaintext. And if n is not, we had a 1.
# This leaves us with just two plaintext candidates.
# Furthermore, we can test 'a' and see that it is a QR, so a^e will always be one. This means that n is QR => the bit in the plaintext was 1

plaintext = []
for c in ciphertext:
	if pow(c,(p-1)//2,p) == 1:
		plaintext.append(1)
	else:
		plaintext.append(0)
plaintext_in_long = 0
for b in plaintext:
	plaintext_in_long *= 2
	plaintext_in_long += b

from Crypto.Util.number import *
# print(long_to_bytes(plaintext_in_long))


#########################################################

def iterative_gcd(a,b):
	if a < b:
		a,b = b,a
	while b != 0:
		a,b = b,a%b
	return a

N = 14905562257842714057932724129575002825405393502650869767115942606408600343380327866258982402447992564988466588305174271674657844352454543958847568190372446723549627752274442789184236490768272313187410077124234699854724907039770193680822495470532218905083459730998003622926152590597710213127952141056029516116785229504645179830037937222022291571738973603920664929150436463632305664687903244972880062028301085749434688159905768052041207513149370212313943117665914802379158613359049957688563885391972151218676545972118494969247440489763431359679770422939441710783575668679693678435669541781490217731619224470152467768073
e1 = 12886657667389660800780796462970504910193928992888518978200029826975978624718627799215564700096007849924866627154987365059524315097631111242449314835868137
e2 = 12110586673991788415780355139635579057920926864887110308343229256046868242179445444897790171351302575188607117081580121488253540215781625598048021161675697
c1 = 14010729418703228234352465883041270611113735889838753433295478495763409056136734155612156934673988344882629541204985909650433819205298939877837314145082403528055884752079219150739849992921393509593620449489882380176216648401057401569934043087087362272303101549800941212057354903559653373299153430753882035233354304783275982332995766778499425529570008008029401325668301144188970480975565215953953985078281395545902102245755862663621187438677596628109967066418993851632543137353041712721919291521767262678140115188735994447949166616101182806820741928292882642234238450207472914232596747755261325098225968268926580993051
c2 = 14386997138637978860748278986945098648507142864584111124202580365103793165811666987664851210230009375267398957979494066880296418013345006977654742303441030008490816239306394492168516278328851513359596253775965916326353050138738183351643338294802012193721879700283088378587949921991198231956871429805847767716137817313612304833733918657887480468724409753522369325138502059408241232155633806496752350562284794715321835226991147547651155287812485862794935695241612676255374480132722940682140395725089329445356434489384831036205387293760789976615210310436732813848937666608611803196199865435145094486231635966885932646519

# print(extendedEucldeanAlgorithm(e1,e2))
# print(extendedEucldeanAlgorithm(e1,N))
# print(extendedEucldeanAlgorithm(N,e2))
# print(extendedEucldeanAlgorithm(c1,c2)) # This exceeds the recursion depth, so we should implement an iterative version of the EEA to calculate this, similar to the iterative version of the CGD algorithm. But it is not necesary to solve this challenge.

# The key idea to solve this problem is that if I can get a nonzero expression in the form of a*p^e while operating with modulo N, I can get p since p = gcd(a*p^e,N). We know this because the first term is multiple an p and not of q (since it is a nonzero value of mod N).
# To find this expression, we strongly use the fact that (a*p+b*q)^e = (a*p)^e + (b*q)^e mod N. This is because all the intermediate terms in the expansion of the Binomial Theorem will be multiple of pq, which is 0 mod N.

multipleOfP = pow(c1,e2,N)*pow(7,e1*e2,N)-pow(c2,e1,N)*pow(3,e1*e2,N) % N # Since the powers distribute, this will result in something like a*p^{e1e2}
p = iterative_gcd(multipleOfP,N)
assert(p>1)
assert(N%p == 0)
print(p)
print(N//p)
