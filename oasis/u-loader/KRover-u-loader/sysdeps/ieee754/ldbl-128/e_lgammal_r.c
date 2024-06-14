/*                                                      lgammal
 *
 *      Natural logarithm of gamma function
 *
 *
 *
 * SYNOPSIS:
 *
 * long double x, y, lgammal();
 * extern int sgngam;
 *
 * y = lgammal(x);
 *
 *
 *
 * DESCRIPTION:
 *
 * Returns the base e (2.718...) logarithm of the absolute
 * value of the gamma function of the argument.
 * The sign (+1 or -1) of the gamma function is returned in a
 * global (extern) variable named sgngam.
 *
 * The positive domain is partitioned into numerous segments for approximation.
 * For x > 10,
 *   log gamma(x) = (x - 0.5) log(x) - x + log sqrt(2 pi) + 1/x R(1/x^2)
 * Near the minimum at x = x0 = 1.46... the approximation is
 *   log gamma(x0 + z) = log gamma(x0) + z^2 P(z)/Q(z)
 * for small z.
 * Elsewhere between 0 and 10,
 *   log gamma(n + z) = log gamma(n) + z P(z)/Q(z)
 * for various selected n and small z.
 *
 * The cosecant reflection formula is employed for negative arguments.
 *
 *
 *
 * ACCURACY:
 *
 *
 * arithmetic      domain        # trials     peak         rms
 *                                            Relative error:
 *    IEEE         10, 30         100000     3.9e-34     9.8e-35
 *    IEEE          0, 10         100000     3.8e-34     5.3e-35
 *                                            Absolute error:
 *    IEEE         -10, 0         100000     8.0e-34     8.0e-35
 *    IEEE         -30, -10       100000     4.4e-34     1.0e-34
 *    IEEE        -100, 100       100000                 1.0e-34
 *
 * The absolute error criterion is the same as relative error
 * when the function magnitude is greater than one but it is absolute
 * when the magnitude is less than one.
 *
 */

/* Copyright 2001 by Stephen L. Moshier <moshier@na-net.ornl.gov>

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, see
    <http://www.gnu.org/licenses/>.  */

#include <math.h>
#include <math_private.h>
#include <float.h>

static const _Float128 PIL = L(3.1415926535897932384626433832795028841972E0);
static const _Float128 MAXLGM = L(1.0485738685148938358098967157129705071571E4928);
static const _Float128 one = 1;
static const _Float128 huge = LDBL_MAX;

/* log gamma(x) = ( x - 0.5 ) * log(x) - x + LS2PI + 1/x P(1/x^2)
   1/x <= 0.0741 (x >= 13.495...)
   Peak relative error 1.5e-36  */
static const _Float128 ls2pi = L(9.1893853320467274178032973640561763986140E-1);
#define NRASY 12
static const _Float128 RASY[NRASY + 1] =
{
  L(8.333333333333333333333333333310437112111E-2),
 L(-2.777777777777777777777774789556228296902E-3),
  L(7.936507936507936507795933938448586499183E-4),
 L(-5.952380952380952041799269756378148574045E-4),
  L(8.417508417507928904209891117498524452523E-4),
 L(-1.917526917481263997778542329739806086290E-3),
  L(6.410256381217852504446848671499409919280E-3),
 L(-2.955064066900961649768101034477363301626E-2),
  L(1.796402955865634243663453415388336954675E-1),
 L(-1.391522089007758553455753477688592767741E0),
  L(1.326130089598399157988112385013829305510E1),
 L(-1.420412699593782497803472576479997819149E2),
  L(1.218058922427762808938869872528846787020E3)
};


/* log gamma(x+13) = log gamma(13) +  x P(x)/Q(x)
   -0.5 <= x <= 0.5
   12.5 <= x+13 <= 13.5
   Peak relative error 1.1e-36  */
static const _Float128 lgam13a = L(1.9987213134765625E1);
static const _Float128 lgam13b = L(1.3608962611495173623870550785125024484248E-6);
#define NRN13 7
static const _Float128 RN13[NRN13 + 1] =
{
  L(8.591478354823578150238226576156275285700E11),
  L(2.347931159756482741018258864137297157668E11),
  L(2.555408396679352028680662433943000804616E10),
  L(1.408581709264464345480765758902967123937E9),
  L(4.126759849752613822953004114044451046321E7),
  L(6.133298899622688505854211579222889943778E5),
  L(3.929248056293651597987893340755876578072E3),
  L(6.850783280018706668924952057996075215223E0)
};
#define NRD13 6
static const _Float128 RD13[NRD13 + 1] =
{
  L(3.401225382297342302296607039352935541669E11),
  L(8.756765276918037910363513243563234551784E10),
  L(8.873913342866613213078554180987647243903E9),
  L(4.483797255342763263361893016049310017973E8),
  L(1.178186288833066430952276702931512870676E7),
  L(1.519928623743264797939103740132278337476E5),
  L(7.989298844938119228411117593338850892311E2)
 /* 1.0E0L */
};


/* log gamma(x+12) = log gamma(12) +  x P(x)/Q(x)
   -0.5 <= x <= 0.5
   11.5 <= x+12 <= 12.5
   Peak relative error 4.1e-36  */
static const _Float128 lgam12a = L(1.75023040771484375E1);
static const _Float128 lgam12b = L(3.7687254483392876529072161996717039575982E-6);
#define NRN12 7
static const _Float128 RN12[NRN12 + 1] =
{
  L(4.709859662695606986110997348630997559137E11),
  L(1.398713878079497115037857470168777995230E11),
  L(1.654654931821564315970930093932954900867E10),
  L(9.916279414876676861193649489207282144036E8),
  L(3.159604070526036074112008954113411389879E7),
  L(5.109099197547205212294747623977502492861E5),
  L(3.563054878276102790183396740969279826988E3),
  L(6.769610657004672719224614163196946862747E0)
};
#define NRD12 6
static const _Float128 RD12[NRD12 + 1] =
{
  L(1.928167007860968063912467318985802726613E11),
  L(5.383198282277806237247492369072266389233E10),
  L(5.915693215338294477444809323037871058363E9),
  L(3.241438287570196713148310560147925781342E8),
  L(9.236680081763754597872713592701048455890E6),
  L(1.292246897881650919242713651166596478850E5),
  L(7.366532445427159272584194816076600211171E2)
 /* 1.0E0L */
};


/* log gamma(x+11) = log gamma(11) +  x P(x)/Q(x)
   -0.5 <= x <= 0.5
   10.5 <= x+11 <= 11.5
   Peak relative error 1.8e-35  */
static const _Float128 lgam11a = L(1.5104400634765625E1);
static const _Float128 lgam11b = L(1.1938309890295225709329251070371882250744E-5);
#define NRN11 7
static const _Float128 RN11[NRN11 + 1] =
{
  L(2.446960438029415837384622675816736622795E11),
  L(7.955444974446413315803799763901729640350E10),
  L(1.030555327949159293591618473447420338444E10),
  L(6.765022131195302709153994345470493334946E8),
  L(2.361892792609204855279723576041468347494E7),
  L(4.186623629779479136428005806072176490125E5),
  L(3.202506022088912768601325534149383594049E3),
  L(6.681356101133728289358838690666225691363E0)
};
#define NRD11 6
static const _Float128 RD11[NRD11 + 1] =
{
  L(1.040483786179428590683912396379079477432E11),
  L(3.172251138489229497223696648369823779729E10),
  L(3.806961885984850433709295832245848084614E9),
  L(2.278070344022934913730015420611609620171E8),
  L(7.089478198662651683977290023829391596481E6),
  L(1.083246385105903533237139380509590158658E5),
  L(6.744420991491385145885727942219463243597E2)
 /* 1.0E0L */
};


/* log gamma(x+10) = log gamma(10) +  x P(x)/Q(x)
   -0.5 <= x <= 0.5
   9.5 <= x+10 <= 10.5
   Peak relative error 5.4e-37  */
static const _Float128 lgam10a = L(1.280181884765625E1);
static const _Float128 lgam10b = L(8.6324252196112077178745667061642811492557E-6);
#define NRN10 7
static const _Float128 RN10[NRN10 + 1] =
{
  L(-1.239059737177249934158597996648808363783E14),
  L(-4.725899566371458992365624673357356908719E13),
  L(-7.283906268647083312042059082837754850808E12),
  L(-5.802855515464011422171165179767478794637E11),
  L(-2.532349691157548788382820303182745897298E10),
  L(-5.884260178023777312587193693477072061820E8),
  L(-6.437774864512125749845840472131829114906E6),
  L(-2.350975266781548931856017239843273049384E4)
};
#define NRD10 7
static const _Float128 RD10[NRD10 + 1] =
{
  L(-5.502645997581822567468347817182347679552E13),
  L(-1.970266640239849804162284805400136473801E13),
  L(-2.819677689615038489384974042561531409392E12),
  L(-2.056105863694742752589691183194061265094E11),
  L(-8.053670086493258693186307810815819662078E9),
  L(-1.632090155573373286153427982504851867131E8),
  L(-1.483575879240631280658077826889223634921E6),
  L(-4.002806669713232271615885826373550502510E3)
 /* 1.0E0L */
};


/* log gamma(x+9) = log gamma(9) +  x P(x)/Q(x)
   -0.5 <= x <= 0.5
   8.5 <= x+9 <= 9.5
   Peak relative error 3.6e-36  */
static const _Float128 lgam9a = L(1.06045989990234375E1);
static const _Float128 lgam9b = L(3.9037218127284172274007216547549861681400E-6);
#define NRN9 7
static const _Float128 RN9[NRN9 + 1] =
{
  L(-4.936332264202687973364500998984608306189E13),
  L(-2.101372682623700967335206138517766274855E13),
  L(-3.615893404644823888655732817505129444195E12),
  L(-3.217104993800878891194322691860075472926E11),
  L(-1.568465330337375725685439173603032921399E10),
  L(-4.073317518162025744377629219101510217761E8),
  L(-4.983232096406156139324846656819246974500E6),
  L(-2.036280038903695980912289722995505277253E4)
};
#define NRD9 7
static const _Float128 RD9[NRD9 + 1] =
{
  L(-2.306006080437656357167128541231915480393E13),
  L(-9.183606842453274924895648863832233799950E12),
  L(-1.461857965935942962087907301194381010380E12),
  L(-1.185728254682789754150068652663124298303E11),
  L(-5.166285094703468567389566085480783070037E9),
  L(-1.164573656694603024184768200787835094317E8),
  L(-1.177343939483908678474886454113163527909E6),
  L(-3.529391059783109732159524500029157638736E3)
  /* 1.0E0L */
};


/* log gamma(x+8) = log gamma(8) +  x P(x)/Q(x)
   -0.5 <= x <= 0.5
   7.5 <= x+8 <= 8.5
   Peak relative error 2.4e-37  */
static const _Float128 lgam8a = L(8.525146484375E0);
static const _Float128 lgam8b = L(1.4876690414300165531036347125050759667737E-5);
#define NRN8 8
static const _Float128 RN8[NRN8 + 1] =
{
  L(6.600775438203423546565361176829139703289E11),
  L(3.406361267593790705240802723914281025800E11),
  L(7.222460928505293914746983300555538432830E10),
  L(8.102984106025088123058747466840656458342E9),
  L(5.157620015986282905232150979772409345927E8),
  L(1.851445288272645829028129389609068641517E7),
  L(3.489261702223124354745894067468953756656E5),
  L(2.892095396706665774434217489775617756014E3),
  L(6.596977510622195827183948478627058738034E0)
};
#define NRD8 7
static const _Float128 RD8[NRD8 + 1] =
{
  L(3.274776546520735414638114828622673016920E11),
  L(1.581811207929065544043963828487733970107E11),
  L(3.108725655667825188135393076860104546416E10),
  L(3.193055010502912617128480163681842165730E9),
  L(1.830871482669835106357529710116211541839E8),
  L(5.790862854275238129848491555068073485086E6),
  L(9.305213264307921522842678835618803553589E4),
  L(6.216974105861848386918949336819572333622E2)
  /* 1.0E0L */
};


/* log gamma(x+7) = log gamma(7) +  x P(x)/Q(x)
   -0.5 <= x <= 0.5
   6.5 <= x+7 <= 7.5
   Peak relative error 3.2e-36  */
static const _Float128 lgam7a = L(6.5792388916015625E0);
static const _Float128 lgam7b = L(1.2320408538495060178292903945321122583007E-5);
#define NRN7 8
static const _Float128 RN7[NRN7 + 1] =
{
  L(2.065019306969459407636744543358209942213E11),
  L(1.226919919023736909889724951708796532847E11),
  L(2.996157990374348596472241776917953749106E10),
  L(3.873001919306801037344727168434909521030E9),
  L(2.841575255593761593270885753992732145094E8),
  L(1.176342515359431913664715324652399565551E7),
  L(2.558097039684188723597519300356028511547E5),
  L(2.448525238332609439023786244782810774702E3),
  L(6.460280377802030953041566617300902020435E0)
};
#define NRD7 7
static const _Float128 RD7[NRD7 + 1] =
{
  L(1.102646614598516998880874785339049304483E11),
  L(6.099297512712715445879759589407189290040E10),
  L(1.372898136289611312713283201112060238351E10),
  L(1.615306270420293159907951633566635172343E9),
  L(1.061114435798489135996614242842561967459E8),
  L(3.845638971184305248268608902030718674691E6),
  L(7.081730675423444975703917836972720495507E4),
  L(5.423122582741398226693137276201344096370E2)
  /* 1.0E0L */
};


/* log gamma(x+6) = log gamma(6) +  x P(x)/Q(x)
   -0.5 <= x <= 0.5
   5.5 <= x+6 <= 6.5
   Peak relative error 6.2e-37  */
static const _Float128 lgam6a = L(4.7874908447265625E0);
static const _Float128 lgam6b = L(8.9805548349424770093452324304839959231517E-7);
#define NRN6 8
static const _Float128 RN6[NRN6 + 1] =
{
  L(-3.538412754670746879119162116819571823643E13),
  L(-2.613432593406849155765698121483394257148E13),
  L(-8.020670732770461579558867891923784753062E12),
  L(-1.322227822931250045347591780332435433420E12),
  L(-1.262809382777272476572558806855377129513E11),
  L(-7.015006277027660872284922325741197022467E9),
  L(-2.149320689089020841076532186783055727299E8),
  L(-3.167210585700002703820077565539658995316E6),
  L(-1.576834867378554185210279285358586385266E4)
};
#define NRD6 8
static const _Float128 RD6[NRD6 + 1] =
{
  L(-2.073955870771283609792355579558899389085E13),
  L(-1.421592856111673959642750863283919318175E13),
  L(-4.012134994918353924219048850264207074949E12),
  L(-6.013361045800992316498238470888523722431E11),
  L(-5.145382510136622274784240527039643430628E10),
  L(-2.510575820013409711678540476918249524123E9),
  L(-6.564058379709759600836745035871373240904E7),
  L(-7.861511116647120540275354855221373571536E5),
  L(-2.821943442729620524365661338459579270561E3)
  /* 1.0E0L */
};


/* log gamma(x+5) = log gamma(5) +  x P(x)/Q(x)
   -0.5 <= x <= 0.5
   4.5 <= x+5 <= 5.5
   Peak relative error 3.4e-37  */
static const _Float128 lgam5a = L(3.17803955078125E0);
static const _Float128 lgam5b = L(1.4279566695619646941601297055408873990961E-5);
#define NRN5 9
static const _Float128 RN5[NRN5 + 1] =
{
  L(2.010952885441805899580403215533972172098E11),
  L(1.916132681242540921354921906708215338584E11),
  L(7.679102403710581712903937970163206882492E10),
  L(1.680514903671382470108010973615268125169E10),
  L(2.181011222911537259440775283277711588410E9),
  L(1.705361119398837808244780667539728356096E8),
  L(7.792391565652481864976147945997033946360E6),
  L(1.910741381027985291688667214472560023819E5),
  L(2.088138241893612679762260077783794329559E3),
  L(6.330318119566998299106803922739066556550E0)
};
#define NRD5 8
static const _Float128 RD5[NRD5 + 1] =
{
  L(1.335189758138651840605141370223112376176E11),
  L(1.174130445739492885895466097516530211283E11),
  L(4.308006619274572338118732154886328519910E10),
  L(8.547402888692578655814445003283720677468E9),
  L(9.934628078575618309542580800421370730906E8),
  L(6.847107420092173812998096295422311820672E7),
  L(2.698552646016599923609773122139463150403E6),
  L(5.526516251532464176412113632726150253215E4),
  L(4.772343321713697385780533022595450486932E2)
  /* 1.0E0L */
};


/* log gamma(x+4) = log gamma(4) +  x P(x)/Q(x)
   -0.5 <= x <= 0.5
   3.5 <= x+4 <= 4.5
   Peak relative error 6.7e-37  */
static const _Float128 lgam4a = L(1.791748046875E0);
static const _Float128 lgam4b = L(1.1422353055000812477358380702272722990692E-5);
#define NRN4 9
static const _Float128 RN4[NRN4 + 1] =
{
  L(-1.026583408246155508572442242188887829208E13),
  L(-1.306476685384622809290193031208776258809E13),
  L(-7.051088602207062164232806511992978915508E12),
  L(-2.100849457735620004967624442027793656108E12),
  L(-3.767473790774546963588549871673843260569E11),
  L(-4.156387497364909963498394522336575984206E10),
  L(-2.764021460668011732047778992419118757746E9),
  L(-1.036617204107109779944986471142938641399E8),
  L(-1.895730886640349026257780896972598305443E6),
  L(-1.180509051468390914200720003907727988201E4)
};
#define NRD4 9
static const _Float128 RD4[NRD4 + 1] =
{
  L(-8.172669122056002077809119378047536240889E12),
  L(-9.477592426087986751343695251801814226960E12),
  L(-4.629448850139318158743900253637212801682E12),
  L(-1.237965465892012573255370078308035272942E12),
  L(-1.971624313506929845158062177061297598956E11),
  L(-1.905434843346570533229942397763361493610E10),
  L(-1.089409357680461419743730978512856675984E9),
  L(-3.416703082301143192939774401370222822430E7),
  L(-4.981791914177103793218433195857635265295E5),
  L(-2.192507743896742751483055798411231453733E3)
  /* 1.0E0L */
};


/* log gamma(x+3) = log gamma(3) +  x P(x)/Q(x)
   -0.25 <= x <= 0.5
   2.75 <= x+3 <= 3.5
   Peak relative error 6.0e-37  */
static const _Float128 lgam3a = L(6.93145751953125E-1);
static const _Float128 lgam3b = L(1.4286068203094172321214581765680755001344E-6);

#define NRN3 9
static const _Float128 RN3[NRN3 + 1] =
{
  L(-4.813901815114776281494823863935820876670E11),
  L(-8.425592975288250400493910291066881992620E11),
  L(-6.228685507402467503655405482985516909157E11),
  L(-2.531972054436786351403749276956707260499E11),
  L(-6.170200796658926701311867484296426831687E10),
  L(-9.211477458528156048231908798456365081135E9),
  L(-8.251806236175037114064561038908691305583E8),
  L(-4.147886355917831049939930101151160447495E7),
  L(-1.010851868928346082547075956946476932162E6),
  L(-8.333374463411801009783402800801201603736E3)
};
#define NRD3 9
static const _Float128 RD3[NRD3 + 1] =
{
  L(-5.216713843111675050627304523368029262450E11),
  L(-8.014292925418308759369583419234079164391E11),
  L(-5.180106858220030014546267824392678611990E11),
  L(-1.830406975497439003897734969120997840011E11),
  L(-3.845274631904879621945745960119924118925E10),
  L(-4.891033385370523863288908070309417710903E9),
  L(-3.670172254411328640353855768698287474282E8),
  L(-1.505316381525727713026364396635522516989E7),
  L(-2.856327162923716881454613540575964890347E5),
  L(-1.622140448015769906847567212766206894547E3)
  /* 1.0E0L */
};


/* log gamma(x+2.5) = log gamma(2.5) +  x P(x)/Q(x)
   -0.125 <= x <= 0.25
   2.375 <= x+2.5 <= 2.75  */
static const _Float128 lgam2r5a = L(2.8466796875E-1);
static const _Float128 lgam2r5b = L(1.4901722919159632494669682701924320137696E-5);
#define NRN2r5 8
static const _Float128 RN2r5[NRN2r5 + 1] =
{
  L(-4.676454313888335499356699817678862233205E9),
  L(-9.361888347911187924389905984624216340639E9),
  L(-7.695353600835685037920815799526540237703E9),
  L(-3.364370100981509060441853085968900734521E9),
  L(-8.449902011848163568670361316804900559863E8),
  L(-1.225249050950801905108001246436783022179E8),
  L(-9.732972931077110161639900388121650470926E6),
  L(-3.695711763932153505623248207576425983573E5),
  L(-4.717341584067827676530426007495274711306E3)
};
#define NRD2r5 8
static const _Float128 RD2r5[NRD2r5 + 1] =
{
  L(-6.650657966618993679456019224416926875619E9),
  L(-1.099511409330635807899718829033488771623E10),
  L(-7.482546968307837168164311101447116903148E9),
  L(-2.702967190056506495988922973755870557217E9),
  L(-5.570008176482922704972943389590409280950E8),
  L(-6.536934032192792470926310043166993233231E7),
  L(-4.101991193844953082400035444146067511725E6),
  L(-1.174082735875715802334430481065526664020E5),
  L(-9.932840389994157592102947657277692978511E2)
  /* 1.0E0L */
};


/* log gamma(x+2) = x P(x)/Q(x)
   -0.125 <= x <= +0.375
   1.875 <= x+2 <= 2.375
   Peak relative error 4.6e-36  */
#define NRN2 9
static const _Float128 RN2[NRN2 + 1] =
{
  L(-3.716661929737318153526921358113793421524E9),
  L(-1.138816715030710406922819131397532331321E10),
  L(-1.421017419363526524544402598734013569950E10),
  L(-9.510432842542519665483662502132010331451E9),
  L(-3.747528562099410197957514973274474767329E9),
  L(-8.923565763363912474488712255317033616626E8),
  L(-1.261396653700237624185350402781338231697E8),
  L(-9.918402520255661797735331317081425749014E6),
  L(-3.753996255897143855113273724233104768831E5),
  L(-4.778761333044147141559311805999540765612E3)
};
#define NRD2 9
static const _Float128 RD2[NRD2 + 1] =
{
  L(-8.790916836764308497770359421351673950111E9),
  L(-2.023108608053212516399197678553737477486E10),
  L(-1.958067901852022239294231785363504458367E10),
  L(-1.035515043621003101254252481625188704529E10),
  L(-3.253884432621336737640841276619272224476E9),
  L(-6.186383531162456814954947669274235815544E8),
  L(-6.932557847749518463038934953605969951466E7),
  L(-4.240731768287359608773351626528479703758E6),
  L(-1.197343995089189188078944689846348116630E5),
  L(-1.004622911670588064824904487064114090920E3)
/* 1.0E0 */
};


/* log gamma(x+1.75) = log gamma(1.75) +  x P(x)/Q(x)
   -0.125 <= x <= +0.125
   1.625 <= x+1.75 <= 1.875
   Peak relative error 9.2e-37 */
static const _Float128 lgam1r75a = L(-8.441162109375E-2);
static const _Float128 lgam1r75b = L(1.0500073264444042213965868602268256157604E-5);
#define NRN1r75 8
static const _Float128 RN1r75[NRN1r75 + 1] =
{
  L(-5.221061693929833937710891646275798251513E7),
  L(-2.052466337474314812817883030472496436993E8),
  L(-2.952718275974940270675670705084125640069E8),
  L(-2.132294039648116684922965964126389017840E8),
  L(-8.554103077186505960591321962207519908489E7),
  L(-1.940250901348870867323943119132071960050E7),
  L(-2.379394147112756860769336400290402208435E6),
  L(-1.384060879999526222029386539622255797389E5),
  L(-2.698453601378319296159355612094598695530E3)
};
#define NRD1r75 8
static const _Float128 RD1r75[NRD1r75 + 1] =
{
  L(-2.109754689501705828789976311354395393605E8),
  L(-5.036651829232895725959911504899241062286E8),
  L(-4.954234699418689764943486770327295098084E8),
  L(-2.589558042412676610775157783898195339410E8),
  L(-7.731476117252958268044969614034776883031E7),
  L(-1.316721702252481296030801191240867486965E7),
  L(-1.201296501404876774861190604303728810836E6),
  L(-5.007966406976106636109459072523610273928E4),
  L(-6.155817990560743422008969155276229018209E2)
  /* 1.0E0L */
};


/* log gamma(x+x0) = y0 +  x^2 P(x)/Q(x)
   -0.0867 <= x <= +0.1634
   1.374932... <= x+x0 <= 1.625032...
   Peak relative error 4.0e-36  */
static const _Float128 x0a = L(1.4616241455078125);
static const _Float128 x0b = L(7.9994605498412626595423257213002588621246E-6);
static const _Float128 y0a = L(-1.21490478515625E-1);
static const _Float128 y0b = L(4.1879797753919044854428223084178486438269E-6);
#define NRN1r5 8
static const _Float128 RN1r5[NRN1r5 + 1] =
{
  L(6.827103657233705798067415468881313128066E5),
  L(1.910041815932269464714909706705242148108E6),
  L(2.194344176925978377083808566251427771951E6),
  L(1.332921400100891472195055269688876427962E6),
  L(4.589080973377307211815655093824787123508E5),
  L(8.900334161263456942727083580232613796141E4),
  L(9.053840838306019753209127312097612455236E3),
  L(4.053367147553353374151852319743594873771E2),
  L(5.040631576303952022968949605613514584950E0)
};
#define NRD1r5 8
static const _Float128 RD1r5[NRD1r5 + 1] =
{
  L(1.411036368843183477558773688484699813355E6),
  L(4.378121767236251950226362443134306184849E6),
  L(5.682322855631723455425929877581697918168E6),
  L(3.999065731556977782435009349967042222375E6),
  L(1.653651390456781293163585493620758410333E6),
  L(4.067774359067489605179546964969435858311E5),
  L(5.741463295366557346748361781768833633256E4),
  L(4.226404539738182992856094681115746692030E3),
  L(1.316980975410327975566999780608618774469E2),
  /* 1.0E0L */
};


/* log gamma(x+1.25) = log gamma(1.25) +  x P(x)/Q(x)
   -.125 <= x <= +.125
   1.125 <= x+1.25 <= 1.375
   Peak relative error = 4.9e-36 */
static const _Float128 lgam1r25a = L(-9.82818603515625E-2);
static const _Float128 lgam1r25b = L(1.0023929749338536146197303364159774377296E-5);
#define NRN1r25 9
static const _Float128 RN1r25[NRN1r25 + 1] =
{
  L(-9.054787275312026472896002240379580536760E4),
  L(-8.685076892989927640126560802094680794471E4),
  L(2.797898965448019916967849727279076547109E5),
  L(6.175520827134342734546868356396008898299E5),
  L(5.179626599589134831538516906517372619641E5),
  L(2.253076616239043944538380039205558242161E5),
  L(5.312653119599957228630544772499197307195E4),
  L(6.434329437514083776052669599834938898255E3),
  L(3.385414416983114598582554037612347549220E2),
  L(4.907821957946273805080625052510832015792E0)
};
#define NRD1r25 8
static const _Float128 RD1r25[NRD1r25 + 1] =
{
  L(3.980939377333448005389084785896660309000E5),
  L(1.429634893085231519692365775184490465542E6),
  L(2.145438946455476062850151428438668234336E6),
  L(1.743786661358280837020848127465970357893E6),
  L(8.316364251289743923178092656080441655273E5),
  L(2.355732939106812496699621491135458324294E5),
  L(3.822267399625696880571810137601310855419E4),
  L(3.228463206479133236028576845538387620856E3),
  L(1.152133170470059555646301189220117965514E2)
  /* 1.0E0L */
};


/* log gamma(x + 1) = x P(x)/Q(x)
   0.0 <= x <= +0.125
   1.0 <= x+1 <= 1.125
   Peak relative error 1.1e-35  */
#define NRN1 8
static const _Float128 RN1[NRN1 + 1] =
{
  L(-9.987560186094800756471055681088744738818E3),
  L(-2.506039379419574361949680225279376329742E4),
  L(-1.386770737662176516403363873617457652991E4),
  L(1.439445846078103202928677244188837130744E4),
  L(2.159612048879650471489449668295139990693E4),
  L(1.047439813638144485276023138173676047079E4),
  L(2.250316398054332592560412486630769139961E3),
  L(1.958510425467720733041971651126443864041E2),
  L(4.516830313569454663374271993200291219855E0)
};
#define NRD1 7
static const _Float128 RD1[NRD1 + 1] =
{
  L(1.730299573175751778863269333703788214547E4),
  L(6.807080914851328611903744668028014678148E4),
  L(1.090071629101496938655806063184092302439E5),
  L(9.124354356415154289343303999616003884080E4),
  L(4.262071638655772404431164427024003253954E4),
  L(1.096981664067373953673982635805821283581E4),
  L(1.431229503796575892151252708527595787588E3),
  L(7.734110684303689320830401788262295992921E1)
 /* 1.0E0 */
};


/* log gamma(x + 1) = x P(x)/Q(x)
   -0.125 <= x <= 0
   0.875 <= x+1 <= 1.0
   Peak relative error 7.0e-37  */
#define NRNr9 8
static const _Float128 RNr9[NRNr9 + 1] =
{
  L(4.441379198241760069548832023257571176884E5),
  L(1.273072988367176540909122090089580368732E6),
  L(9.732422305818501557502584486510048387724E5),
  L(-5.040539994443998275271644292272870348684E5),
  L(-1.208719055525609446357448132109723786736E6),
  L(-7.434275365370936547146540554419058907156E5),
  L(-2.075642969983377738209203358199008185741E5),
  L(-2.565534860781128618589288075109372218042E4),
  L(-1.032901669542994124131223797515913955938E3),
};
#define NRDr9 8
static const _Float128 RDr9[NRDr9 + 1] =
{
  L(-7.694488331323118759486182246005193998007E5),
  L(-3.301918855321234414232308938454112213751E6),
  L(-5.856830900232338906742924836032279404702E6),
  L(-5.540672519616151584486240871424021377540E6),
  L(-3.006530901041386626148342989181721176919E6),
  L(-9.350378280513062139466966374330795935163E5),
  L(-1.566179100031063346901755685375732739511E5),
  L(-1.205016539620260779274902967231510804992E4),
  L(-2.724583156305709733221564484006088794284E2)
/* 1.0E0 */
};


/* Evaluate P[n] x^n  +  P[n-1] x^(n-1)  +  ...  +  P[0] */

static _Float128
neval (_Float128 x, const _Float128 *p, int n)
{
  _Float128 y;

  p += n;
  y = *p--;
  do
    {
      y = y * x + *p--;
    }
  while (--n > 0);
  return y;
}


/* Evaluate x^n+1  +  P[n] x^(n)  +  P[n-1] x^(n-1)  +  ...  +  P[0] */

static _Float128
deval (_Float128 x, const _Float128 *p, int n)
{
  _Float128 y;

  p += n;
  y = x + *p--;
  do
    {
      y = y * x + *p--;
    }
  while (--n > 0);
  return y;
}


_Float128
__ieee754_lgammal_r (_Float128 x, int *signgamp)
{
  _Float128 p, q, w, z, nx;
  int i, nn;

  *signgamp = 1;

  if (! isfinite (x))
    return x * x;

  if (x == 0)
    {
      if (signbit (x))
	*signgamp = -1;
    }

  if (x < 0)
    {
      if (x < -2 && x > -50)
	return __lgamma_negl (x, signgamp);
      q = -x;
      p = floorl (q);
      if (p == q)
	return (one / fabsl (p - p));
      _Float128 halfp = p * L(0.5);
      if (halfp == floorl (halfp))
	*signgamp = -1;
      else
	*signgamp = 1;
      if (q < L(0x1p-120))
	return -__logl (q);
      z = q - p;
      if (z > L(0.5))
	{
	  p += 1;
	  z = p - q;
	}
      z = q * __sinl (PIL * z);
      w = __ieee754_lgammal_r (q, &i);
      z = __logl (PIL / z) - w;
      return (z);
    }

  if (x < L(13.5))
    {
      p = 0;
      nx = floorl (x + L(0.5));
      nn = nx;
      switch (nn)
	{
	case 0:
	  /* log gamma (x + 1) = log(x) + log gamma(x) */
	  if (x < L(0x1p-120))
	    return -__logl (x);
	  else if (x <= 0.125)
	    {
	      p = x * neval (x, RN1, NRN1) / deval (x, RD1, NRD1);
	    }
	  else if (x <= 0.375)
	    {
	      z = x - L(0.25);
	      p = z * neval (z, RN1r25, NRN1r25) / deval (z, RD1r25, NRD1r25);
	      p += lgam1r25b;
	      p += lgam1r25a;
	    }
	  else if (x <= 0.625)
	    {
	      z = x + (1 - x0a);
	      z = z - x0b;
	      p = neval (z, RN1r5, NRN1r5) / deval (z, RD1r5, NRD1r5);
	      p = p * z * z;
	      p = p + y0b;
	      p = p + y0a;
	    }
	  else if (x <= 0.875)
	    {
	      z = x - L(0.75);
	      p = z * neval (z, RN1r75, NRN1r75) / deval (z, RD1r75, NRD1r75);
	      p += lgam1r75b;
	      p += lgam1r75a;
	    }
	  else
	    {
	      z = x - 1;
	      p = z * neval (z, RN2, NRN2) / deval (z, RD2, NRD2);
	    }
	  p = p - __logl (x);
	  break;

	case 1:
	  if (x < L(0.875))
	    {
	      if (x <= 0.625)
		{
		  z = x + (1 - x0a);
		  z = z - x0b;
		  p = neval (z, RN1r5, NRN1r5) / deval (z, RD1r5, NRD1r5);
		  p = p * z * z;
		  p = p + y0b;
		  p = p + y0a;
		}
	      else if (x <= 0.875)
		{
		  z = x - L(0.75);
		  p = z * neval (z, RN1r75, NRN1r75)
			/ deval (z, RD1r75, NRD1r75);
		  p += lgam1r75b;
		  p += lgam1r75a;
		}
	      else
		{
		  z = x - 1;
		  p = z * neval (z, RN2, NRN2) / deval (z, RD2, NRD2);
		}
	      p = p - __logl (x);
	    }
	  else if (x < 1)
	    {
	      z = x - 1;
	      p = z * neval (z, RNr9, NRNr9) / deval (z, RDr9, NRDr9);
	    }
	  else if (x == 1)
	    p = 0;
	  else if (x <= L(1.125))
	    {
	      z = x - 1;
	      p = z * neval (z, RN1, NRN1) / deval (z, RD1, NRD1);
	    }
	  else if (x <= 1.375)
	    {
	      z = x - L(1.25);
	      p = z * neval (z, RN1r25, NRN1r25) / deval (z, RD1r25, NRD1r25);
	      p += lgam1r25b;
	      p += lgam1r25a;
	    }
	  else
	    {
	      /* 1.375 <= x+x0 <= 1.625 */
	      z = x - x0a;
	      z = z - x0b;
	      p = neval (z, RN1r5, NRN1r5) / deval (z, RD1r5, NRD1r5);
	      p = p * z * z;
	      p = p + y0b;
	      p = p + y0a;
	    }
	  break;

	case 2:
	  if (x < L(1.625))
	    {
	      z = x - x0a;
	      z = z - x0b;
	      p = neval (z, RN1r5, NRN1r5) / deval (z, RD1r5, NRD1r5);
	      p = p * z * z;
	      p = p + y0b;
	      p = p + y0a;
	    }
	  else if (x < L(1.875))
	    {
	      z = x - L(1.75);
	      p = z * neval (z, RN1r75, NRN1r75) / deval (z, RD1r75, NRD1r75);
	      p += lgam1r75b;
	      p += lgam1r75a;
	    }
	  else if (x == 2)
	    p = 0;
	  else if (x < L(2.375))
	    {
	      z = x - 2;
	      p = z * neval (z, RN2, NRN2) / deval (z, RD2, NRD2);
	    }
	  else
	    {
	      z = x - L(2.5);
	      p = z * neval (z, RN2r5, NRN2r5) / deval (z, RD2r5, NRD2r5);
	      p += lgam2r5b;
	      p += lgam2r5a;
	    }
	  break;

	case 3:
	  if (x < 2.75)
	    {
	      z = x - L(2.5);
	      p = z * neval (z, RN2r5, NRN2r5) / deval (z, RD2r5, NRD2r5);
	      p += lgam2r5b;
	      p += lgam2r5a;
	    }
	  else
	    {
	      z = x - 3;
	      p = z * neval (z, RN3, NRN3) / deval (z, RD3, NRD3);
	      p += lgam3b;
	      p += lgam3a;
	    }
	  break;

	case 4:
	  z = x - 4;
	  p = z * neval (z, RN4, NRN4) / deval (z, RD4, NRD4);
	  p += lgam4b;
	  p += lgam4a;
	  break;

	case 5:
	  z = x - 5;
	  p = z * neval (z, RN5, NRN5) / deval (z, RD5, NRD5);
	  p += lgam5b;
	  p += lgam5a;
	  break;

	case 6:
	  z = x - 6;
	  p = z * neval (z, RN6, NRN6) / deval (z, RD6, NRD6);
	  p += lgam6b;
	  p += lgam6a;
	  break;

	case 7:
	  z = x - 7;
	  p = z * neval (z, RN7, NRN7) / deval (z, RD7, NRD7);
	  p += lgam7b;
	  p += lgam7a;
	  break;

	case 8:
	  z = x - 8;
	  p = z * neval (z, RN8, NRN8) / deval (z, RD8, NRD8);
	  p += lgam8b;
	  p += lgam8a;
	  break;

	case 9:
	  z = x - 9;
	  p = z * neval (z, RN9, NRN9) / deval (z, RD9, NRD9);
	  p += lgam9b;
	  p += lgam9a;
	  break;

	case 10:
	  z = x - 10;
	  p = z * neval (z, RN10, NRN10) / deval (z, RD10, NRD10);
	  p += lgam10b;
	  p += lgam10a;
	  break;

	case 11:
	  z = x - 11;
	  p = z * neval (z, RN11, NRN11) / deval (z, RD11, NRD11);
	  p += lgam11b;
	  p += lgam11a;
	  break;

	case 12:
	  z = x - 12;
	  p = z * neval (z, RN12, NRN12) / deval (z, RD12, NRD12);
	  p += lgam12b;
	  p += lgam12a;
	  break;

	case 13:
	  z = x - 13;
	  p = z * neval (z, RN13, NRN13) / deval (z, RD13, NRD13);
	  p += lgam13b;
	  p += lgam13a;
	  break;
	}
      return p;
    }

  if (x > MAXLGM)
    return (*signgamp * huge * huge);

  if (x > L(0x1p120))
    return x * (__logl (x) - 1);
  q = ls2pi - x;
  q = (x - L(0.5)) * __logl (x) + q;
  if (x > L(1.0e18))
    return (q);

  p = 1 / (x * x);
  q += neval (p, RASY, NRASY) / x;
  return (q);
}
strong_alias (__ieee754_lgammal_r, __lgammal_r_finite)
