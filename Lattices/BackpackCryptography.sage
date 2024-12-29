# SOURCE:

# import random
# from collections import namedtuple
# import gmpy2
# from Crypto.Util.number import isPrime, bytes_to_long, inverse, long_to_bytes
#
# FLAG = b'crypto{??????????????????????????}'
# PrivateKey = namedtuple("PrivateKey", ['b', 'r', 'q'])
#
# def gen_private_key(size):
#     s = 10000
#     b = []
#     for _ in range(size):
#         ai = random.randint(s + 1, 2 * s)
#         assert ai > sum(b)
#         b.append(ai)
#         s += ai
#     while True:
#         q = random.randint(2 * s, 32 * s)
#         if isPrime(q):
#             break
#     r = random.randint(s, q)
#     assert q > sum(b)
#     assert gmpy2.gcd(q,r) == 1
#     return PrivateKey(b, r, q)
#
#
# def gen_public_key(private_key: PrivateKey):
#     a = []
#     for x in private_key.b:
#         a.append((private_key.r * x) % private_key.q)
#     return a
#
#
# def encrypt(msg, public_key):
#     assert len(msg) * 8 <= len(public_key)
#     ct = 0
#     msg = bytes_to_long(msg)
#     for bi in public_key:
#         ct += (msg & 1) * bi
#         msg >>= 1
#     return ct
#
#
# def decrypt(ct, private_key: PrivateKey):
#     ct = inverse(private_key.r, private_key.q) * ct % private_key.q
#     msg = 0
#     for i in range(len(private_key.b) - 1, -1, -1):
#          if ct >= private_key.b[i]:
#              msg |= 1 << i
#              ct -= private_key.b[i]
#     return long_to_bytes(msg)
#
#
# private_key = gen_private_key(len(FLAG) * 8)
# public_key = gen_public_key(private_key)
# encrypted = encrypt(FLAG, public_key)
# decrypted = decrypt(encrypted, private_key)
# assert decrypted == FLAG

# print(f'Public key: {public_key}')
# print(f'Encrypted Flag: {encrypted}')

# DATA

pub_key = [260288377891444370372615148009023640057294926547602419331406531383682223097787288755377467188515435381259752760746, 322734358011758862401399370931929863052553602421714393280581187496537763321855751120439457234561080720455397490349, 88092359256403564783665281993130133541226601877969436905267415353041909757324746080398461245281826552421872983184, 601684701300110945921036937572461050140352984401874675917155063594305583314408001377505387079690115000992094388032, 193814643850628739958152744041743058858484088269609293429408490294552345005365776962194365813796130165113184925621, 51510606914703888409341761261103125433754505248101513818740574350196563260563818621033222936301769697693287778876, 502702742677974540308798846750017003106263447846689040491266463798703222616320168069962523670400796196343460832764, 86989835783586738140883150201327374176124588410464188692884973334241681514702306716383785095564084499563152815246, 515511378187957676256419959601984383408150348796281656976955880729383340611785836962788715725367023923811376366815, 119845178983025037005174732553931706284024826223176718982111213579707091766057320315419827781508690979405126062061, 207867794910968434026003881920029657224591376925067493713968219177352819759854486838459675245909787840416982457750, 239399986603216503029402544900610984881160101923294396792665204486222975420081300661354603175384772323551980155480, 306665236132315336961576566094908486196981556971172170145299174389720334940261512384837950321772782983903454058725, 558130280550827068212352576387713811027468233905173944680355562037815257403446113128895937326412940859588204361963, 123471925832174980344066571541132411467266736109103860421447462536930482316849470378251137263190870093702164003085, 146089706629012142384661350988216882483919264673129621404831339166566056469572087759748854086023354002641923689390, 446097892684389219719742914373867457099954499449824602532333181169038249081395758983133906564840000962001976506057, 204029934276059225352901134714823317920576872465404508059719045291560482057171052793698580294637069578017200124432, 412333373143000457741307988470055504576675151299345387733692618218275177027643785881042018546460452418506341967356, 171418413940299360322712423004114364681865276057786947919043883366302567169869592290151559269290446563185553350080, 401593473337411114258578268223784182795068785564101722335215736591292301602077751376477881087346810602041717163104, 204003688543820354337113938494979311981574571424756883928855286926734578790400322291262042466654212377708831289347, 555612926496986208337317871061684502803594375654879680702581403987248292734014139717756900004905653768133795128973, 462785612281910846822645629160953231999037081137615204334672445418078665808070086646804794186256411131615189487813, 77961961618173276050791733447969083544152711482614563228085622136316525792569658878271751219358260960116292497570, 517789370221435419776588087490678991824021927945387533283088388790482913301281733115458601414668206432512998904516, 281870328340314395150658482932699114581743200279996227099530744754750289102031518563761975024621347281374162044877, 60204977937304337797770029325498234132893935850995809547662640467737007197647697381430963693698522962733473746281, 395936787836195675178388359277761575381601972138693830435288611414489963379399027975388601714741876831895709497105, 90921357930302550361827901642067284191268695594120415817202534786924330392421221829361546010764453051928814876700, 238523907687908075601117120608130752369082206676107364350347208286323115036939777325067473364465438898353765093766, 277515010021988996116595000889051160811249034599876556819610707794016612800585201793339332495839495779526504613846, 187215937497318890199135284983515062319988136636108170852591598862524363777870331888216170582220867500042557737272, 411220029331367081136918789112083235781237730079305782620378994961505282090962448446931628731751970521853108685376, 433613620456520979627974441205441942311133790647897226320388205340695256818608765746266662314499649013982035729731, 509613591091334719216567967380183602959933686617275815879939870258332674755345348802452058256788513837941126219238, 352708166022264045150842358964512080203788453464883319778517822047480718640858804837886057264514786742694419419735, 486272357335492500753956372299255798603575392697018451800774427752724312455328655650777691830508441976819499348269, 1291533249748053824342851185451970324561531056195308125673915619130780992270420765078102812914222570167615953050, 520707501920546816250915326019351261090208813534492143136485743644939372232638461802625700978801768541842624647274, 272359456788721692618768612190222453304838934916628492701462591276450281926223118982602858211688086607842351391495, 119534191144397164327417397593964021477488683311215644770010641745736480039094209273092223959694752862193314087240, 394945131470603614379767959704654538029557537489316246092982427107641617479545488843535929537498546432123287486437, 395979428475608101765230328218274625986674115712051764903732593018454264017781340199795540039285257513438842708672, 322101629493887220159199019582810892418957941946300752245249462093036697035162212557261470168522953435341905295650, 60610073299031334532969727880668989046838926047395613981473675505442500833244137863225398782029541439420403686372, 492582431835005621441922899995666806499437611069193099072247918597047415020628078410849119945608854080040163699375, 356290614124448077864884136922409291617128370298210212357882465167338600485728936925448944675136056707929560080237, 469737185578879122378016959759297464132272432425745272107998534197014940235018335349886398896979254122985841196030, 522871107234918024128768136315123497251902274681110489386594944387181296826024289163431880961506314580935567743910, 407151723612481391724375429193917289623669496278028982297086458062111012958436324350527302865535766565677711383191, 597354385774970715448797740483856119139152021834911852144490298736330354118482480147237280491305029710326837274157, 541106433608213985607913120402276000940203625086988929757276286018099336445558864548353610869729642196223750468493, 417269959280528548156948994397262973057821055108288565091113745409730174626359955737489143948177504667498654245449, 165844467199853002181647516786815801413939363188955720855463610698066730208657222822269457713666541555820608908443, 54875733171006797537647859403084623422036246809497621662400918381496284440644503330411668895858884933248328986102, 465819050441857934210906305127374377291850450707906416261994960542649394393702032587209990932960399224341143990297, 369322923825463715724411404444452360125845865658673947242361968271863944079047696087621731311243573179527276498509, 553158781749591211954659671173145767949897795287325677938373702443265138456771264711232588438786042792968904732769, 409812013938165700887519758386718364160025926340003407045361393371862966914817952304595560620453598830906305966865, 494654868138757552768371639418237489264099471894419220273147503624077564865563661914136003656825657044284503346448, 583613295252460993144403074130901622751986348055784728175987246652496523293580989652454868505577305787293683850652, 45623098408168398769971239387495928980835555721564847009059790575158770295430426790200773274288087331109699336204, 39196430635656777174378129146834600960125068266405306877726260536750371354188413207203531511343645151492477471286, 269811462520469960288594953357779332541515563494806499705455036716689694055741096626927182558039773813984145657639, 56129158162087034209035841739296133948708529713411817898928727109770418208078239244331640522507423413446203417794, 524210107239750288249530336771864024916995632570549267972428294539507299820629133801771958736839361325798918246415, 74499040113803277306263886217659673645883223840279171192334357737741618882160648968176974754905084576184804774369, 537566085689080717108870646705458338163437075433046077845999622035879463636776663759447985884960181167857417860517, 67053890181708018909161683393261532526993578729770554741021482840348299866927821016301415949708659944497709907470, 226687291544149270579995169198961617407190234578516732237756117257869929434434889879973211444301745820066870869034, 30119130560797352224094299766590747178156378314088092947830899847927767559391822485618397327733723834195435500170, 273554685078063587415670757725663508130498751998110442807136494763920302805098071555958936900406570453984774374060, 87980277743580170573607118853300224477595233902389343863665172738347967268089655736029345194767280704236057718111, 415325115863346791298232938393411393462777451386243842830553121689594926353646948497680883539360608323603975987452, 291860381996369849963997875749710331697722876276851205203280910491894467229365951220031470367159168511107680106262, 554653569462940342418063467925252548314485118886100002832290030505991378878498660088540140703141291011055029173137, 323189774384600834625013268084915768916855209746568551595158521873406091567687194674213765428238599317205811518692, 271805885895959097314720980134407607645324820417975238169874050425279962478579515969226563851125481000349196674810, 273580504244152469063405670227951980303621824057876058884978331188257821496852334599050020207990127348359965113465, 89994080154200685717636930068317931325931168723237899144166312528962957042842197915530047017893088501681215899095, 179903529806043505032581494908566846659773117049401056767669943330229935007822437549131470977810261112485254094386, 337553339737054880017288314951575451797426862530219763936855885416298554494199226261714888518914541341927073075939, 55576723594346882914517616915509260915444308762551400560217462518909289055446940809390878002725822401595827206530, 16748220768196858904499918524709172735166549515085689048938405549141121222201553686060172878474455615920723669801, 317380564633191615800168658676142557493413060315417096622564923156521630376263849705099633192226251101432134441153, 533990888376667129575141849433166253104032964155895368357797314378260092470904627861359175864364684662961150582207, 51339665999563119517609216115086272052501396280925354694804471629521639434841281422984348587180771099209184749005, 598751671521816401429095343374521592165563401213195481604556405443389323390172923217639290327197434030974530635632, 502516418942980462174586089858060912235797554801782186782319843655355616321036648106166017773986280053024012403712, 96757697084956246010025820107260538706827163135748809142998937362457169471061108292297066769079020843197361323396, 160715027762704553320571142674023737670353756130518440136900430091151963142004047232920245715827837173811719927140, 279138292123840748082780689543574043699162822819208361733228093396335579794292477744981338016264347327181324984710, 76445842054689324523514421681098261857514827631364695255959418519245612571199123499205752729124353901548286671941, 383675319414133753635121914615218464358220814208747712016103562476157464944897131756675168140846189629485664787044, 260741648290568813857849033448155840373964568801980310694295413631289231242930901519918814851819352903132884286000, 572815144956474380133620797676157654285774633299428534205241845335783095326631133195133798583360396067031309578073, 326258465939147178368353573060965288327891986807699582822092415027094204965326681853802159504539722937811913340954, 270266570242986488258809014590807152136633692716132669770748395523214017062557603428657196661342410476403164567952, 594635668324174018778140793057815156885870465660609865234586849536688338135131804764199647040009222634146148815637, 112066852946512058163194024984815176069074331367673763590415760757313750687675218022751871678411881684718198988959, 72643140251973593561700085821570131390914743121754868577502110904091989089708201436984242838820806097191225214858, 418558767829526524235103555737958351573183096833081038769308995724925326439890724874671213539641031754157727776067, 196559288823369030489094238610617412012659194878611686482089456487889879135369906410569754176462601644487717691079, 484475844260869041475828428835126624027291693283800645559775410528136122290210564467730445814182429120097372738911, 397895531572254423225385975618860549078025992059379971480526615942245245283818149065605766495091059477544617632303, 173098235745543952336517747078283517802667869630628062474315240281111485771833849083340162673485620557610425012773, 395438744730241817782361196255681827924847041028664896503460681041226871979986416514203189980456170013127549062319, 470021990867207717347003710359490169212637212255796418181420825247262094876084196634243149241752002339736588912053, 116393009019558569654503508922282193810180596603376432764270301486325221610807518426481578453602546466299515294456, 312679236344738874814229979243462639486594453393064312671149009880980836289564409215088541509970023077739205203468, 125633612607015147027292740679836345332097512816636698981581758992992116056276272361001165705597842757882238693825, 550545747650576990464265884382499274254872311986381675090751886824037811235625095205217845451891396561893492715391, 582344947379262203945082609921047126789902458640974947174265099323728700596079597139164883619347159500887293859913, 597445807393853093495564866081359122814348105478914638258595339515168987499771664924728981250079847198831836930965, 203086100710322798737771097067197649738932976573837729229038404179992238381339090779534246758253939763462200026384, 366083021996787911206272856169665720981308167177143125303074466648545813452157612764258146407782634619278092168081, 568425067761875823198893591966757461338470700675615033946429149483970138055665377562238998722395767377075284081587, 292063178202410186631443519138674436645163233411161937085629856088259050827382985093506892763617302007759121037731, 572237520943575841301998365238940412928982617335768155394691567092595694943290938278464533099223273214233507106207, 130730938892686892107630262721901246969052318133502728671984157629171554435251506312878040499761922665301495030981, 185117108148352276973404708807613996548096583954940273525781406848525491758486946236965943611210198389159091280333, 37060990092986925132287820152354618271473589014825595897838753632315007172710154561879917551705194656825456571032, 403396730776194870459199627544122636010870768257463359235766775533882938128146112838489577777497432203020030499998, 390519053219213422305599109947414047895590808796368085342860468917268018310638864392199371679272174634278410878307, 128444781947873592602609418783055715736876557725608932301613294446934930933474014020041434831899064316552264614235, 543291373538613455155809248493830432520680330961337677793905220928838352322514565851452650441518480234729892153780, 488514444383813071753894478409325136755661751625837651637348989332739608743318097848609715931362718450900659714726, 345584582429475420526208382863826459005483455209655712636957752389218040279848223862500232738960994712140028026289, 93010878843154734421543561265196548806562081923037074596459052686633775723171466088126269822057315393084026072218, 12533412965882925987419497258660569237455714460582608620237638858642686843645624645184949324869641399446820464020, 562770032030414047557952904910126027215456025343530350248616818594366525600180778011275466074764589844321872364272, 128451705070871056157396910591766296038989235798264982434769256144115712608648937222298167066517556774062311420353, 490278961434267039693706795888817653385586689501848271165345121922956317504140732421546020494675482464550410472502, 212287543946551782522399704940695532581109453008804375002654843122502975490312129477869621998080277682674199046031, 351228167329138957128592454766411142609836239330479331051630155591459798299725613134325016512314887321869487481161, 364056580106158102895694571253671943571916920885795142960090311722444269241247963009814588199874030295862636577768, 323410613174912128865174768949092780979646178505039555025194364419990442219941948707117457621400459111231556621585, 555979459475319018276106133189578589964687373772995549423813902773304274184448885651570001083614054140692063026580, 471645896888183848879918063770091917659270906648819201901346651975957177950753583099047587304484006413716362087065, 595746107902898270905714635379070716651708771264047581902664532594897071557252807014533004074458867603957329534516, 557816517693603351719661411054144374250247040672226934534604151399902780319198098821629853612396635344596388943480, 75653615683769023911143698869320584951015514055697266638646507368530841035631560833198288977975782471517557394092, 386729218862361591185009654369415880766336899946663823664818477204172007165198875809899277634660190797185025579614, 393108265477944240661308455550612796769200470498502703905073280606596277788078742986164286625262059483908055127428, 365065802583204450004435661912506592532468753723399406740663534070289404492293680764078659588454240436160849321237, 343474792575856700080726394177083134771079426798042359193966109700850531408037245425173307797050676647933775237484, 449270583610225180914452784540333562631570453995885992409935055758994173533991695282410200635020830187612444056607, 152477148608000973940085532267319492932629609199964217167273279315109403426434432473053141371160594251975646390787, 215758046810520029171417357963508549726865838830930981174495643955719506571398771447950049727234258305885220507020, 388644732079570479249894814593945177309689613386566508292336098907992239994635374799070003303374928382563877494312, 33174396496627497383579687586254392056231321534282758587681567913835717050445163816449882425899904436708697640574, 293328356964375951072242072976851267186828242468018707810599907336525314670450502681522283876131924077746023996643, 292804486280753504026674757794166015519590385505528937148184945726179320137391480944836180610675717906694042510411, 278315915715399524055936806996907092937794467054749462150463756152176847617395557111508306851465386462011262385630, 103884040577296119486012754822466682224025370872916939490159319500421058932999421365377738193002421767097172706341, 111463652129659874006915288174831654634146152513640366449316440114829594116719772451443937868409442532699879776869, 475152124260969797265060453354454799124845717445357239027249597786029156307488697633998763174770332805926500738683, 220597335944113643138040910019263318251616203954548724660953303915089233301354511542662225751359573592406567125779, 460838912228809947843094986154780694841314087685379351551107763714127613789323858795003275958350186756130179585099, 140183105024444619512158726537661171898184380568070161231133567610679885584873426652521827961950911404383912561621, 100258312363732149931656549158547430770829888011033153048299126820116382987576385251423248018523377569893042593237, 405290867185420593972711092047858403431415058957648108848290712855486205273135789994549738296802436972506132007215, 256955277068974586752505570703153051582682851398012077625721880852140628262494489158976679841716540706155916871083, 598549159802958710401362839481280273681933957841944662088149512518476573000011803427513695903373248355980692446393, 308263288681016807641714404434630877489176754884164049322636274036076916608089721011418189274379096133290778967977, 8342859679410179631729508842147337278025979845268212054683951869690623917413242667876438120214556608223950514653, 439895086294728342454449126955941890844828534912064877350830376651948083146591737071488196253116258629344717466258, 91881226123407259536921548434174382841001791568169293198769940131230256611806601058471105885254628422499512141440, 377266324363766263400630205724731218877243980277025204567255708828742612895175112462476548764041808998472515741645, 116673062533491873681185131034931580572262852751033929144868000941380674942800523209276875356733463592351603448680, 57238242567269156027816815706946539463493497634492900168501163766058930300567388616552782194562204025116893421410, 589774086517371498643669747060802896861503240906569357013148621028285639980785543690656162836694887880501379427719, 299125626128142030020988742420785075132372751191528474146303145649473683269241675130370288768899920531289674244113, 304688395547666111898109663337992917557352968749730125549180444196974698222351897080702952045364871753888027443342, 482739851676824100473920409347215848398789318900117561465297399614115666738614477259195415015272146741220074932513, 223546862652113236935862556158177901803806229739994958195958127700830125319767534179348037800919714328649801362322, 150425375689725206871177727482717625428944121456212788472446922564113718518867636855506280578641904259888006038685, 143374483079122348274771015162872747263883105211675941440480524305910827744168931572051691220561136775398957657059, 128633351158033453796356108560970241527889904619011394383277988372280437398843373552825146090070247278923404428730, 249625701621261544438183108711205773478938560640571200325127252485779481701078452759513943692466279038851599018511, 330098489762871879773681019559732262466172018773272582308614672671671001199307865518506835519360693927579848132122, 97272570979206528424127336981516817168566955222510512261839537633559389914877185855268875504270285494647179225542, 74718841026645027941391238796126141775030441881552798010185595153873780524478674202965665888738730228577064111032, 59009205910055868684561742529451214311094377006520731342399475542159755492342086349692903126315766192176134558364, 147954106872023713951463145691216475084430006306060416221364896834795769425749212897622105818492094458111589403860, 555992830271936179812799550002813412539390844307434015514327261249472823762801208645240806724751727789206958497458, 459223438688559571249116685914649450095540121668933258507609746609794374539448063463326591749261191192370815662117, 571393209200912648822312183637054598815269397678580613768957089116765483865121162495918269935152288322187647411253, 177286186824084038346767370297094817293812392957721642873053028629715330336525966361030541938870465423944241324109, 587491267113142201933590855412985429253948652679543672927232780837039223665539177593879438262959884768626979925026, 121073719992748558849282996502703446279240313956823650619682240860630373634948798695523514085879310433388769297911, 326992821821879354165502695961028240084978294787383957718963930070776372845305415470613976088436935751047043512627, 55897462658973985554837453480984923331777372313619418297379632868358904708526448610515770876401568010074036247, 474281517111080897542557845865286041097457650249727914745876496139882777461227076272058949306156001543709356614827, 40880447006931568560802817837347288973549001731224760995212446282117046967004745589464560120352241602331262757637, 199377582253379978414081552664345738394226248383486423477706857549702059554694037264958719644482986837756496613246, 67583806809325529684782118654476643411516600285151896093983454855502714712133346956141976654071062935812737453191, 452546341988439193982297214011678766258506490290911066090290647614068455151806621409756646430532117713333419814200, 63154079944843452528208874183624055953361990336542165468695871390964383215223885775202331596927466794955939855669, 334551033942583568474606741839213957101383590286251155186668543235920975897931743928357631453433934808796703330473, 437000125133660712403788025992205090698484430907657894066272071296035483375078474260228687865444802416063967634962, 79996507523856267942889507576300340014719316733731500178081582238768493408405645914333660158893963260211116177267, 136957270824318341027124989034235585855646981093281453761145461440890955503793684517186875995202144027265329969201, 280204753198588906275980318398478729285287961542920285529979812275266316580102545873587416433404212703776245726478, 537734235993878341769434982550042490365981751251428660237179942734374485415922424357453321846937022328664895920607, 498357256878949571854248804622370932859926894994690120526235824883083753765132401863605500892090016764206939698756, 593183658694608014094449104249771865876595121367209656250471158771632486392533730913932393504513988512194994235126, 471525047958971655208534107052287853913949987926476676197514310320411235020283503103705707957701802098089852040455, 515550195522086342769232739520750768345601850976320014312405876943691700378141377151414091085616391824613041356222, 229784654767967355149909497709811119368560654037206880944035229827691011815016913131119422451043820980926353941725, 217169654015051285238559403576147518221573574303291047729813710960725792892550445720464605476174663800328177597453, 445865555254101127829958642102675927687168710569707725467286103803938348116926832834254624089519482737855028080263, 83946997792088073746354410376458121354546477090285151121896293987266118404260723878401677521317330022928683440101, 472119354862263268431251633432424976904384210603399093568806291862332048310282050100842204125396472101319620313029, 46843467515693389983627938872598324284244171067988563260495985345821466093790361374194115630948136965603015643581, 277302589126799360982750111603442360555051934636756171066424884732490616874962892980005637968336486277371298105284, 37796860324947087933757452089444569583341754367174335457777874936449439863762482510080776848131952814291888228252, 329201662631483519275850208043421059140347420462580260818216051307977255139454956805683010032538225008290753339066, 410958260744814455637908317160979333881545314073457621559204623145344687279791103290567233048673594441768330391568, 391184069150039601440639067557184862816991051523817132396666190555512106382919904848895224325098711230221328168893, 341778180155955688649827271577690269253924367106359453768062062983194302766144996692233530585116870343939549344048, 482885184891891026832543019680624112333051960746415331234199075553060933581630480706330420552017650892318225421994, 227417029879602291913898154454350465334192275455983368980997243946371067766121862949125088496933933053493304375082, 131891059077173823480681683274809296700667012054595015489329798567668841455882278540434006611778254351469315756836, 103977685400575936876007245351080422734569291709540152622222483086840011211808484758839889045266405362833100572217, 430039690420862864710328860317916251552162738538460131045295388990486621940999260820629946807283129550503791042360, 336054039341779369078755981618338727567421739252984379060088264565052065080902800664605952509539644185937023210384, 414650487301520195860820485747902373712957920758077572646321108690388934071745453432265035539090489903222596288408, 589576193361941267176015154197092338077060428665767302320550323024382985851379047593411265195718688560873123744185, 218382333622730104159935425552756841820388948639519923842495333910150980936866251625988964615764772159578862214025, 2542356543181698813075957157401385706512468063673241076844194782908937880847391489213422972872487843717747974071, 19012712934576590810330358701965194246607393288484627129050567402003333386833300009773236871643918870071025370112, 261459449945270346696260426170010104493420330959761424072408598127181246567262293489464049721489266230568086023687, 393057872763078249377870634042993942252544393136978340205701555086856991894130814830449765311294161681995357980571, 31706670785655144489258744219717253455873175486088498446357251628824725653898017817866303775262383346847940227722, 352845629675989592022318947558037109666715372268243939061740352176833050420783754677666411876876865226448815643420, 579523499570692157776642365278787278074363193157128877724940050501652213832135926670258239249988403301949338255538, 534781322034571849183222718240938369181782069830117215874801137890227720544463940037268498986061166881241864175911, 293947547828174245724554745263997068016996177889470503383528004805559670712802640725469343616840367100443153534752, 20256488447976344493484944853334005566670073013412177398480406734598723283264289836587474269370253077015786359305, 475307340957345844876811923970449788514706891727480716267956523131203845997503382023500463149439850432076379159007, 9532193777031501443256432870520743234491840911054244783623102207162388499144070592024440812057106927678514406207, 30376455906399256126534181227692885553266283699913099449205248506625206632827693466133644861846223565145288661633, 310323302397755654510284518631138079981439265632852684852876254116989091445393487579911757256043570018377230904180, 407387187512823516321154849212634322952876110252179375736935664859854509488826142049903683991617538259494461983206, 211765773488300500716796064525502573590145731868562963063378748592341237756767589777342751660513980880169703658019, 118119996850569812443799306306875048213209686043987665925365129711742300844060014347898233682054000714610165352429, 456288037921986114882644161559494182818651772335241262800783776696209877706906644069180867207555069937013686421247, 321798425169971169912343295962697085577508076571119888196289113181080013814133443673221049860354996979915353284172, 324976521789232911848337505841284978746361536915903971011255451438673522500730537005137182463678372897314198988595, 395621759076694189110473461483468243816716472466025836871653502259071450104902960119128530517955567830675053452079, 539300517585750216948117617165146582589224695990488749904551961039061424290129525221984586819908097960720708938354, 29279302128607422250205549520059282069518559284219582605487413142781822276106373289432262133635053599391124926385, 554047387889265384869858916477442181952403597250555948392949469296673941793381852004501421929101000148453680659392, 117780825424837288494479009381221759361151487239443821133102414888864152904732196195473813006762420646998382258677, 513764579681988270425418630365712613073908798769959690739998792846173650211508078458011456784363312999085649615413, 421686906289957894155024887354760839265000904451245772175308131137467275202489561700021659858819873604538650489994, 420037832423259525388141394520857134457021929872555809167052539034540217718781279113965175987358081438109891771580, 36451605745112040602804954235939462081346791770310181663631699054048414835838956409055640948581948016033003511333, 65866443469866248828119099994518897685990064406903627156894902667947376070679854260383038634727146436274230980496, 27676413701492447763964945205769602759768347623741189980278225943728587187940271050634054217590942659542302722334, 500312789935788689187812810985806111797362028998353677843819125485045576943472901976055579663665267905809820905862, 520064354401353505774803720281331074080600746212325401527048530022713769008774050816490541356142354757805595273068, 495854656037423684061417113244964481431602915324717605570975073575414392233479237472936965636133612283412033946051, 91739870792230359210043046401786959190045929124141709653873699398574077579395785555200462734509728806350612588545, 484531754577892922131892661653620989224382080321025512011181426678442547912964573223048519566085582623517825865418, 112714684344084391078866980839255594355187885339701715768009153551270432322826715969989728340963213693095849427668, 404429204723786534299525333122163342588586991421902466839808468487493896330979873416105908841447535426923681220957, 92404742424217640040375362532444172359091402942418950195520660310216430170054358290537973281349284862065214755739, 224043393969043013532511880223075809120842856165608086692928112430171548569493398551019081676395857489451126409940, 4305919427803364191555497499680058924116536587126751817219863902878291078989381194676206640960307162723876513248]
encrypted_flag = 45690752833299626276860565848930183308016946786375859806294346622745082512511847698896914843023558560509878243217521

# SOLUTION

# I'm going to set a Lattice generated by the following 273 rows 
# (2, 0, ... , 0, pub_key[0])
# (0, 2, ... , 0, pub_key[1])
# ...
# (0, 0, ... , 2, pub_key[271])
# (1, 1, ... , 1, flag)

# If the bits of the message are x_0, x_1, ..., x_271, then the vector
# (a_0, a_1, ..., a_271, 0) where a_i = 1 - 2*x_i will be on the lattice, and will be fairly short
# since a_i^2 = 1. Therefore, each a_i will tell us the i-th bit of the hidden message.

m = []
# I extracted these values to variables because I wanted to experiment with them. The values 2 and 1 seemed quite arbitraty to me.
# Which combination of values make the LLL algorithm find the solution where each word is used at most once?
# Aside from (2,1), (3,1) and (4,2) work. I still can't see a pattern.
words_weight = 2
flag_weight = 1

for i in range(272):
  row = [0 for _ in range(273)]
  row[272] = pub_key[i]
  row[i] = words_weight 
  m.append(row)

row = [flag_weight for i in range(273)]
row[272] = encrypted_flag
m.append(row)

mat = Matrix(m)

ans = mat.LLL()
short_vector = []

for i in range(273):
  isCorrect = True
  for j in range(272):
    if ans[i][j] != flag_weight and ans[i][j] != flag_weight - words_weight:
      isCorrect = False
      break
  if ans[i][272] != 0:
    isCorrect = False
  if isCorrect:
    short_vector = ans[i]
    break

print(short_vector)
if short_vector == []:
  print(ans)
assert short_vector != []
# I have to reverse the bit array given the way I defined the lattice. And I throw away the last coordinate since is 0 and we won't use it anymore.
short_vector = [short_vector[271-i] for i in range(272)]

bit_string = '0b'
for i in range(272):
    bit_string += '1' if short_vector[i] == flag_weight - words_weight else '0'

message_int = int(bit_string, 2)
message = bytes.fromhex(hex(message_int)[2:])

print(message)











######################################################################

# Other ideas that didn't work:

# # If I have q I can find the private key, because I can call a SVP on the lattice generetated by 
# # <(1, pub_key[0]), (0, q)>, which will surely return the vector (r^{-1} mod q, priv_key[0]), since 
# # the second coordinate is a number in (10000, 20000).
# # Another way to crack this system knowing q is using that priv[0] is in (10000, 20000). I can brute force this by 
# # trying all the possible values, getting r = pub[0]*priv[0]^{-1} mod q, and testing if the corresponding r satisfies
# # priv[i] > sum(priv[0:i])
#
#
#
# # Since q is part of the private key, I'm going to try to guess it.
# # The idea is that I have 272 seemingly random reminders mod q, so the candidate 
# # would be the next prime of the maximum number among all of the public key.
#
# upper_bound = 0
# for a in pub_key:
#     upper_bound = max(upper_bound, a)
#
# # print('upper_bound =', upper_bound)
#
# # With this upper_bound, I call the upper_bound.next_prime() method in sage to get:
# candidate_q = 601684701300110945921036937572461050140352984401874675917155063594305583314408001377505387079690115000992094388039
# candidate_q = 601684701300110945921036937572461050140352984401874675917155063594305583314408001377505387079690115000992094388547
# # This doesn't work because numbers are too big ;(
