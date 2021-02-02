--
-- PostgreSQL database dump
--

-- Dumped from database version 13.1 (Debian 13.1-1.pgdg100+1)
-- Dumped by pg_dump version 13.1 (Debian 13.1-1.pgdg100+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.users (username, fullname, discordid, created_at) FROM stdin;
kaves20	Kasper Møller Vestergaard	269923758750433281	2021-01-07 16:04:30.164593+00
olnor18	Oliver Lind Nordestgaard	357236132766941214	2021-01-07 16:07:06.082534+00
essoe20	Esben Damkjær Sørensen	381589614638530581	2021-01-28 14:03:03.514159+00
caspe20	Casper Kjærsgaard Jensen	218143948172951553	2021-01-29 15:25:51.255744+00
nicol20	Nicolaj Aalykke Hansen	247341254629654529	2021-01-29 20:08:40.745414+00
huwab20	Hudayfa Hassan Ige Waberi	202565644015632385	2021-01-29 20:09:17.797613+00
stefa20	Stefan Profft Larsen	210329454575222784	2021-01-29 20:16:30.333835+00
betur20	Berfin Flora Turan	688836088361386017	2021-01-29 20:20:38.951925+00
jobau19	Joachim Rasztar Baumann	204637681764925441	2021-01-29 21:28:39.340499+00
jasun20	Janik Søndergaard Sunke	750720526472970311	2021-01-29 21:46:15.6167+00
bekut20	Berkan Kütük	494622004218036254	2021-01-29 22:22:35.843915+00
chkra19	Christoffer Schurmann Krath	182937684803715072	2021-01-29 22:23:23.720268+00
olhei20	Oliver Heine	352746432777814018	2021-01-30 06:35:18.433172+00
rasmj20	Rasmus Enemark Jacobsen	212274920078573568	2021-01-30 09:01:26.900628+00
siugg16	Simon Banke Uggerhøj	212655084838846466	2021-01-30 09:51:29.812259+00
semon20	Sebastian Christensen Mondrup	618340245770993665	2021-01-30 10:34:34.274154+00
maxha20	Max Sandberg Hansen	319259299132080128	2021-01-30 11:16:33.845695+00
albni20	Albert Gejr Nielsen	380340154663174146	2021-01-30 11:27:49.080242+00
jecom20	Jesper Gade Commerou	300379292200861696	2021-01-30 12:26:44.718539+00
maeng20	Mathias Jeppesen Engmark	248015852417449994	2021-01-30 12:48:29.19476+00
caan516	Casper Brøchner Andresen	221316695124344832	2021-01-30 14:14:52.593399+00
linea11	Line Andersen	692755588370923551	2021-01-30 14:21:31.559907+00
alval20	Alex Valentiner	200991441709694977	2021-01-30 14:34:28.360756+00
phnie19	Phillip Løvenhardt Vincent Nielsen	233655419367718914	2021-01-30 14:59:22.532736+00
lobo	Lone Borgersen	804348010758537277	2021-01-30 16:54:56.845961+00
meha419	Mette Marie Storgaard Hansen	741634770500583527	2021-01-30 17:03:35.583987+00
anirv20	Anton Valdemar Dahlin Irvold	254615388543778816	2021-01-30 17:10:54.637888+00
achri20	Anton Lucas Schou Christensen	346663094203842561	2021-01-30 17:13:51.395313+00
dasmi20	Daniel Smidstrup	693597739568726148	2021-01-30 17:19:14.813608+00
faalb19	Fatma Mondher Al-Beidhany	779731041950498836	2021-01-30 18:42:17.914284+00
jafar20	Jasan Abdikalif Farah	394995714914123777	2021-01-30 20:29:53.462944+00
cefre17	Cecilie Fredsgaard	694229105369153654	2021-01-30 22:32:38.863738+00
heank16	Henrik Ankersø	237713917697064961	2021-01-30 22:40:16.251664+00
magun20	Mathias Kold Gundersen	318831166734204938	2021-01-30 22:45:05.325023+00
almat20	Alexander Bundgaard Matzen	124125692152512512	2021-01-30 22:56:19.410183+00
assiv20	Ashvikan Sivabalaa	402550614724182018	2021-01-30 23:38:24.858235+00
ospra20	Oskar Præstholm	159650499891691520	2021-01-31 07:49:58.246697+00
oschr20	Oskar Løjtved Møller Christensen	322734828002869248	2021-01-31 10:33:38.954894+00
viroe20	Victor Johannes Larsen Røer	145301884662448128	2021-01-31 10:53:24.860243+00
fayus20	Farhiya Mohamoud Adan Yusuf	753279331421388840	2021-01-31 10:54:05.716347+00
sivin20	Sigurd Skelmose Vind	232918293369847808	2021-01-31 10:54:21.517159+00
frpou20	Frederik Angantyr Bjørn Keldmann Poulsen	272806015064473600	2021-01-31 10:54:23.18786+00
kapan20	Karl-Emil Pantzar	749701715267158207	2021-01-31 10:57:29.801029+00
oshan20	Oskar Mellor Hansen	239333055372853249	2021-01-31 11:00:17.240586+00
frand18	Frederik Mertz Andersen	153940476808921089	2021-01-31 11:09:46.431419+00
elind20	Emil Kjær Lind	140090551222534144	2021-01-31 11:14:42.682915+00
mikkh20	Mikkel Duus Normann Hansen	234945032761769984	2021-01-31 11:15:46.521824+00
frtoe20	Frederik Primdahl Tønnes	359695220272791554	2021-01-31 11:20:02.231184+00
tobso20	Tobias Vedsted Sørensen	560109289973481472	2021-01-31 11:26:11.543314+00
sitag20	Simon Krüger Tagge	118415837660053513	2021-01-31 11:44:04.621658+00
mikke20	Mikkel Plagborg Andersen	156494788223434752	2021-01-31 11:47:57.242418+00
niver20	Nicolaj Risbjerg Iversen	210766190711275520	2021-01-31 11:55:54.191104+00
chrij18	Christoffer Peter Jensen	201022016113868800	2021-01-31 12:06:01.288552+00
okdem19	Okan Demirtas	180020826760937473	2021-01-31 12:23:59.367617+00
auste18	Anders Østerby	147044330425679872	2021-01-31 12:28:38.189202+00
srgna20	Srivarsan Gnanachandran	711360567511744512	2021-01-31 12:29:31.352341+00
fjoer20	Frederikke Lan Jørgensen	757914012523429929	2021-01-31 12:52:56.667998+00
janpe20	Jan Pedersen	172280037054087168	2021-01-31 13:04:20.626839+00
macoh20	Martin Conrad Hansen	214329239116316673	2021-01-31 13:05:10.029566+00
jesch20	Jens Christian Laue Schütt	267378107705458689	2021-01-31 13:05:11.48741+00
rathy20	Rasmus Bentzen Thye	297827532776931329	2021-01-31 13:05:35.372202+00
vidra20	Victor Woydowski Dralle	749696334893678777	2021-01-31 13:15:27.367817+00
pandr20	Patrick Holmquist Andreasen	425254988051120130	2021-01-31 13:30:03.757472+00
nibas18	Nida Basaran	503904119950671883	2021-01-31 13:44:57.507699+00
llaur19	Louie Steen Laursen	141598814745133056	2021-01-31 13:59:44.469084+00
jokaa17	Jonas Solhaug Kaad	229036287573753856	2021-01-31 14:06:47.757885+00
mschl16	Mathias Schlüter	274670441891627009	2021-01-31 14:19:55.295258+00
alkoe20	Alexander Victor Dybendal Koefoed	219869198539685888	2021-01-31 14:28:23.213267+00
majuu19	Magnus Stuart Juul	246062835501760512	2021-01-31 14:39:03.765332+00
jetof20	Jens Christian Toftdahl	221354844299067403	2021-01-31 14:39:56.936561+00
kaso819	Kasper Østergaard Sørensen	544162566176505866	2021-01-31 14:56:31.834407+00
madch19	Mads Munch Christensen	368503071195660298	2021-01-31 15:13:53.818583+00
emmjo20	Emma Kirstine Jørgensen	568339813686837248	2021-01-31 16:00:06.185365+00
sifug20	Simon Mathias Fugl	173078361147441154	2021-01-31 16:03:05.7827+00
alnoe20	Alexander Vinding Nørup	122472394412654595	2021-01-31 16:23:19.184233+00
kscha14	Kasper Jøhnk Schäffer	169890024601550848	2021-01-31 17:00:56.19015+00
sival19	Simonas Valiulis	541399074633678866	2021-01-31 17:34:19.113706+00
dabah20	Daniel Bahrami	112656990353776640	2021-01-31 17:36:12.382179+00
dcele20	Dilara Eda Celepli	447882210880520192	2021-01-31 17:59:08.840633+00
diluu20	Dinh Phu Luu	274665429346287617	2021-01-31 18:18:49.669215+00
sehan19	Sebastian Hundebøl Hansen	126436845973274625	2021-01-31 18:20:02.980001+00
patan14	Patrick Andersen	758042613537308713	2021-01-31 18:36:08.636553+00
hgard20	Hampus Fink Gärdström	166201094857293824	2021-01-31 18:50:08.816283+00
sispe20	Simon dos Reis Spedsbjerg	309314848502579202	2021-01-31 18:59:47.626523+00
nickj20	Nicklas Bruun Jensen	93741694901563392	2021-01-31 19:05:50.389363+00
jobro19	Johan Severin Brockstedt	99186997691715584	2021-01-31 19:18:15.711662+00
olris20	Oliver Snede Rise	302187263435997184	2021-01-31 19:18:51.411984+00
chbru20	Christian Brügger	229877539424829440	2021-01-31 19:28:40.677933+00
mikch19	Mikkel Dolleris Christensen	174098760069021696	2021-01-31 19:33:50.376381+00
mikkl20	Mikkel Priisholm Larsen	274610152592900096	2021-01-31 20:06:15.091005+00
cmath20	Camilla Mathiesen	245238939085045760	2021-01-31 20:11:06.615869+00
emspa15	Emil Spangenberg	766209872072802305	2021-01-31 20:29:00.274409+00
thten19	Theis Agerskov Tengs	119850289468669952	2021-01-31 21:21:00.131274+00
casje19	Casper Fenger Jensen	189446748291203072	2021-01-31 21:22:12.505044+00
kasto16	Kasper Stokholm	113649965091258375	2021-01-31 22:14:24.844656+00
fwvuo18	Fwu Jenn Vuong	113699193486311426	2021-01-31 22:35:16.225503+00
jepla20	Jeppe Holst Larsen	209047661188218891	2021-01-31 23:39:30.872222+00
haped20	Hans Rosenfeldt Pedersen	155694481138515968	2021-02-01 00:00:42.619127+00
olnym19	Oliver Busk Nymann	227756332684410880	2021-02-01 07:41:48.735224+00
angad20	Andreas Christoffer Bjerregaard Gade	177497812303347713	2021-02-01 08:12:10.308593+00
aali319	Anbareen Ali	623433690323615744	2021-02-01 08:45:02.888986+00
luhav20	Lucas Wolthers Havenkvist	133648554538434560	2021-02-01 08:45:07.06802+00
niwal19	Nicolai Blak Walther	580700250902102023	2021-02-01 08:46:04.446709+00
mikkn20	Mikkel Bonde Nielsen	233204737611137025	2021-02-01 08:46:05.300183+00
emkar18	Emilie Helgesen Karlsson	486416704101154816	2021-02-01 08:55:51.850219+00
ostho20	Oskar Kjær Thomsen	161905275819917312	2021-02-01 09:35:12.673966+00
kdavi16	Kasper Schultz Davidsen	277058998186803212	2021-02-01 09:49:22.974726+00
pahan19	Patrick Hansen	448786895842050080	2021-02-01 09:53:40.566139+00
mmunk19	Markus Kristoffer Kofod Munk	403618104728354826	2021-02-01 10:22:03.045148+00
olste20	Oliver Steen	105734305237446656	2021-02-01 10:24:44.953312+00
emima20	Emil Madsen	420991030121463809	2021-02-01 10:28:41.43256+00
ogyor20	Oguz Yorulmaz	177465072766025729	2021-02-01 10:53:12.145206+00
marcp20	Marcus Brun Pedersen	96149699383283712	2021-02-01 11:33:06.303159+00
owagn20	Oliver Dahl Wagner	363040075216453643	2021-02-01 11:37:57.031946+00
vbruu20	Victor Frank Bruun	234038062579974144	2021-02-01 12:06:33.441257+00
akirk20	Anne Cathrine Kirkegaard	360433738590453760	2021-02-01 12:19:29.627218+00
akjen20	Aksel Thyregod Jensen	228197640079278080	2021-02-01 12:24:06.037751+00
laask20	Lasse Askholm	128617493173501952	2021-02-01 12:26:09.4556+00
laand19	Lars Andersson	230049801788588033	2021-02-01 12:34:38.059638+00
thlan20	Theis Juul Langlands	766203176964980748	2021-02-01 12:41:34.276745+00
jobel20	Jonas Lyngsø Beltoft	226403443869220864	2021-02-01 12:54:58.173797+00
sield20	Simon Sebastian Neess Eldahl	416956236970590210	2021-02-01 12:56:22.755473+00
olhin20	Oliver Rødtjer Hinsch	276022139214233603	2021-02-01 12:59:15.583743+00
thrai20	Thomas Raith	168123567026864128	2021-02-01 13:00:19.615564+00
laujj20	Lau Jul Jensen	263065548051447808	2021-02-01 13:23:40.095475+00
chkis20	Christian Kisholt	192349245607641090	2021-02-01 13:28:15.938019+00
small11	Sandra Malling-Larsen	694959108524343367	2021-02-01 13:58:58.494442+00
salid18	Samir Al Idrissi	485927744513769484	2021-02-01 14:01:15.926629+00
daly19	Danny Hoang-Nguyen Ly	283251456029753355	2021-02-01 14:10:47.029451+00
gokri20	Gorm Emil Smedegaard Krings	242709524300038148	2021-02-01 14:18:21.178838+00
alert20	Ali Can Erten	233650260612874241	2021-02-01 14:25:07.01177+00
magso19	Magnus Kingo Sørensen	377174295329374230	2021-02-01 14:27:21.74557+00
vamor20	Valon Morina	598234474420895764	2021-02-01 14:35:49.439469+00
pernh20	Pernille Stoltze Hansen	233331741958471680	2021-02-01 14:53:19.067376+00
tsoer18	Tobias Sørensen	187201690003308544	2021-02-01 14:57:56.737952+00
magns20	Magnus Kjær Sørensen	688464335969976364	2021-02-01 15:00:23.61557+00
tobip20	Tobias Solberg Pedersen	288339163491729408	2021-02-01 15:02:37.607875+00
tchri20	Thomas Christensen	214014715565834240	2021-02-01 15:02:50.136441+00
viboy20	Victor Andreas Boye	106029425388195840	2021-02-01 15:02:51.248144+00
freni20	Frederik Nørager Horne Nielsen	244216739229990913	2021-02-01 15:02:56.202446+00
aikos13	Aino Karita Kostiainen	764072998718013471	2021-02-01 15:03:01.380684+00
argas16	Ardit Gashi	228598060664487938	2021-02-01 15:03:02.859509+00
yubay20	Yusuf Baysoz	346694067918209034	2021-02-01 15:03:32.628117+00
sikar16	Simon Karing	150783857245814786	2021-02-01 15:03:36.475904+00
berte20	Marc Lindegård Weller Bertelsen	127840773096996864	2021-02-01 15:04:13.626798+00
maha520	Mathias André Kragelund Hansen	133376051391758336	2021-02-01 15:04:45.307914+00
chbre20	Christian Bressendorff	323510224176545792	2021-02-01 15:04:45.409284+00
nihee20	Nicolas Emil Blente Heeks	214485685770387457	2021-02-01 15:04:54.817405+00
mafed20	Malthe Harndahl Feddern	347745404634398720	2021-02-01 15:05:40.302148+00
vabir20	Valdemar Nørup Birk	427527092452851734	2021-02-01 15:05:41.473972+00
nkris19	Nikolas James Duus Kristiansen	782740083715080266	2021-02-01 15:06:04.468224+00
trkal20	Troels Kaldau	758249038159151111	2021-02-01 15:06:08.009+00
eeikr20	Eesha Asim Choudhry Ikram	779764522902618122	2021-02-01 15:06:12.383657+00
fujam20	Fuad Hassan Jama	377287158509076480	2021-02-01 15:06:18.961856+00
suroe20	Sune Roed	319930196444708864	2021-02-01 15:06:23.321989+00
mabyl20	Marcus Glifberg Byllemos	344416122256228362	2021-02-01 15:06:26.471221+00
clbec20	Claus Christian Aahøj Bech	804012615923269662	2021-02-01 15:06:28.623716+00
casti19	Casper McGuire Stillinge	270504043275747329	2021-02-01 15:06:42.893334+00
mitof20	Mike Toftum	232527785732734978	2021-02-01 15:06:45.104548+00
aabdi07	Abdullahi Abdirahman Mohamed	430817909795717121	2021-02-01 15:06:58.156637+00
ibdem20	Ibrahim Isa Demir	231517828082171905	2021-02-01 15:07:03.916191+00
andem20	Anders Lindhardt Madsen	805789784009736192	2021-02-01 15:07:53.31481+00
nikol20	Nikolaj Rydeberg Jensen	119205619059130371	2021-02-01 15:09:13.441214+00
farah20	Faezeh Rahimi	730950083142484069	2021-02-01 15:09:49.182473+00
jedie20	Jesper Bork Diederichsen	359687354144915457	2021-02-01 15:12:10.616899+00
nmari19	Nithurshan Mariyananthajesuthasan	371989878856089601	2021-02-01 15:13:34.468355+00
mani320	Mathias Nørager Horne Nielsen	244217712186884107	2021-02-01 15:15:54.896973+00
hanas20	Hamed Nashir	779384176003514429	2021-02-01 15:17:50.358166+00
simok20	Simon Skovgaard Kristensen	703254248028241991	2021-02-01 15:18:28.696465+00
munad20	Muhamad Hussein Nadali	538440083091488768	2021-02-01 15:19:19.097036+00
morni20	Morten Hovedskov Nielsen	272821538712190977	2021-02-01 15:22:45.19403+00
nanie20	Nadia Kærsgaard Niemier	756231853467500545	2021-02-01 15:28:35.564687+00
ramel20	Rasmus Meldgaard	176388371403374592	2021-02-01 16:12:01.749508+00
dangu19	Dan Nguyen	143806534932103168	2021-02-01 16:23:13.040954+00
lerav10	Leivan Ravi	487234039418191873	2021-02-01 17:07:56.675599+00
aneje16	Anette Aviana Jensen	313765634792226817	2021-02-01 22:12:39.912358+00
saabi19	Saad Ali Abid	687424784367485160	2021-02-01 22:15:03.942134+00
abtho16	Abraham Thomsen	497739516271001601	2021-02-01 23:23:47.628038+00
\.


--
-- PostgreSQL database dump complete
--

