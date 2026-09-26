"""Data sampel: dokumen resmi negara Republik Indonesia.

Seluruh dokumen di bawah ini adalah dokumen resmi negara yang **bebas hak
cipta** berdasarkan Pasal 42 Undang-Undang Nomor 28 Tahun 2014 tentang Hak
Cipta (tidak ada hak cipta atas peraturan perundang-undangan dan dokumen resmi
negara).  Teks diambil dari Wikisource bahasa Indonesia (id.wikisource.org).

Karena sistem perbandingan bekerja pada alfabet A-Z (26 huruf), seluruh teks
dinormalkan dengan :func:`normalize_az`: huruf dijadikan kapital dan semua
karakter selain A-Z (spasi, tanda baca, angka, baris baru) dihilangkan.
"""

import random

# ---------------------------------------------------------------------------
# Metadata sumber (untuk sitasi pada Bab 4 skripsi)
# ---------------------------------------------------------------------------
SUMBER = {
    "Pancasila": "https://id.wikisource.org/wiki/Pancasila",
    "Proklamasi": "https://id.wikisource.org/wiki/Proklamasi_Kemerdekaan_Indonesia",
    "Pembukaan UUD 1945": "https://id.wikisource.org/wiki/Undang-Undang_Dasar_Negara_Republik_Indonesia_Tahun_1945",
    "Pasal UUD 1945": "https://id.wikisource.org/wiki/Undang-Undang_Dasar_Negara_Republik_Indonesia_Tahun_1945",
    "Pasal UU ITE": "https://id.wikisource.org/wiki/Undang-Undang_Republik_Indonesia_Nomor_11_Tahun_2008",
    "Pasal UU PDP": "https://id.wikisource.org/wiki/Undang-Undang_Republik_Indonesia_Nomor_27_Tahun_2022",
}

# ---------------------------------------------------------------------------
# Isi dokumen (transkripsi setia dari Wikisource)
# ---------------------------------------------------------------------------
PANCASILA = """
Ketuhanan Yang Maha Esa
Kemanusiaan yang adil dan beradab
Persatuan Indonesia
Kerakyatan yang dipimpin oleh hikmat kebijaksanaan dalam permusyawaratan dan perwakilan
Keadilan sosial bagi seluruh rakyat Indonesia
"""

# Teks proklamasi menggunakan ejaan lama asli tahun 1945.
PROKLAMASI = """
Kami bangsa Indonesia dengan ini menjatakan kemerdekaan Indonesia
Hal-hal jang mengenai pemindahan kekoeasaan d.l.l. diselenggarakan dengan
tjara seksama dan dalam tempo jang sesingkat-singkatnja
Djakarta hari 17 boelan 8 tahoen 05
Atas nama bangsa Indonesia
Soekarno Hatta
"""

PEMBUKAAN_UUD_1945 = """
Bahwa sesungguhnya kemerdekaan itu ialah hak segala bangsa dan oleh sebab itu
maka penjajahan di atas dunia harus dihapuskan karena tidak sesuai dengan
perikemanusiaan dan perikeadilan
Dan perjuangan pergerakan kemerdekaan Indonesia telah sampailah kepada saat
yang berbahagia dengan selamat sentosa mengantarkan rakyat Indonesia ke depan
pintu gerbang kemerdekaan Negara Indonesia yang merdeka bersatu berdaulat adil
dan makmur
Atas berkat rahmat Allah Yang Maha Kuasa dan dengan didorongkan oleh keinginan
luhur supaya berkehidupan kebangsaan yang bebas maka rakyat Indonesia
menyatakan dengan ini kemerdekaannya
Kemudian daripada itu untuk membentuk suatu Pemerintah Negara Indonesia yang
melindungi segenap bangsa Indonesia dan seluruh tumpah darah Indonesia dan
untuk memajukan kesejahteraan umum mencerdaskan kehidupan bangsa dan ikut
melaksanakan ketertiban dunia yang berdasarkan kemerdekaan perdamaian abadi
dan keadilan sosial maka disusunlah Kemerdekaan Kebangsaan Indonesia itu dalam
suatu Undang-Undang Dasar Negara Indonesia yang terbentuk dalam suatu susunan
Negara Republik Indonesia yang berkedaulatan rakyat dengan berdasarkan kepada
Ketuhanan Yang Maha Esa Kemanusiaan Yang Adil dan Beradab Persatuan Indonesia
dan Kerakyatan yang dipimpin oleh hikmat kebijaksanaan dalam Permusyawaratan
Perwakilan serta dengan mewujudkan suatu Keadilan sosial bagi seluruh rakyat
Indonesia
"""

PASAL_UUD_1945 = """
Negara Indonesia ialah Negara Kesatuan yang berbentuk Republik
Kedaulatan berada di tangan rakyat dan dilaksanakan menurut Undang-Undang Dasar
Negara Indonesia adalah negara hukum
Segala warga negara bersamaan kedudukannya di dalam hukum dan pemerintahan dan
wajib menjunjung hukum dan pemerintahan itu dengan tidak ada kecualinya
Tiap-tiap warga negara berhak atas pekerjaan dan penghidupan yang layak bagi
kemanusiaan
Setiap warga negara berhak dan wajib ikut serta dalam upaya pembelaan negara
Setiap orang berhak untuk hidup serta berhak mempertahankan hidup dan
kehidupannya
Setiap orang berhak membentuk keluarga dan melanjutkan keturunan melalui
perkawinan yang sah
Setiap anak berhak atas kelangsungan hidup tumbuh dan berkembang serta berhak
atas perlindungan dari kekerasan dan diskriminasi
Setiap orang berhak mengembangkan diri melalui pemenuhan kebutuhan dasarnya
berhak mendapat pendidikan dan memperoleh manfaat dari ilmu pengetahuan dan
teknologi seni dan budaya demi meningkatkan kualitas hidupnya dan demi
kesejahteraan umat manusia
Setiap orang berhak atas pengakuan jaminan perlindungan dan kepastian hukum
yang adil serta perlakuan yang sama di hadapan hukum
Setiap orang berhak untuk bekerja serta mendapat imbalan dan perlakuan yang
adil dan layak dalam hubungan kerja
Setiap orang bebas memeluk agama dan beribadat menurut agamanya memilih
pendidikan dan pengajaran memilih pekerjaan memilih kewarganegaraan memilih
tempat tinggal di wilayah negara dan meninggalkannya serta berhak kembali
Setiap orang berhak atas kebebasan berserikat berkumpul dan mengeluarkan
pendapat
Setiap orang berhak untuk berkomunikasi dan memperoleh informasi untuk
mengembangkan pribadi dan lingkungan sosialnya serta berhak untuk mencari
memperoleh memiliki menyimpan mengolah dan menyampaikan informasi dengan
menggunakan segala jenis saluran yang tersedia
Setiap orang berhak atas perlindungan diri pribadi keluarga kehormatan
martabat dan harta benda yang dibawah kekuasaannya serta berhak atas rasa aman
dan perlindungan dari ancaman ketakutan untuk berbuat atau tidak berbuat
sesuatu yang merupakan hak asasi
Setiap orang berhak untuk bebas dari penyiksaan dan perlakuan yang merendahkan
derajat martabat manusia dan berhak memperoleh suaka politik dari negara lain
Setiap orang berhak hidup sejahtera lahir dan batin bertempat tinggal dan
mendapatkan lingkungan hidup baik dan sehat serta berhak memperoleh pelayanan
kesehatan
Setiap orang berhak atas jaminan sosial yang memungkinkan pengembangan dirinya
secara utuh sebagai manusia yang bermartabat
Setiap orang berhak mempunyai hak milik pribadi dan hak milik tersebut tidak
boleh diambil alih secara sewenang-wenang oleh siapa pun
Hak untuk hidup hak untuk tidak disiksa hak kemerdekaan pikiran dan hati nurani
hak beragama hak untuk tidak diperbudak hak untuk diakui sebagai pribadi di
hadapan hukum dan hak untuk tidak dituntut atas dasar hukum yang berlaku surut
adalah hak asasi manusia yang tidak dapat dikurangi dalam keadaan apa pun
Setiap orang berhak bebas atas perlakuan yang bersifat diskriminatif atas dasar
apa pun dan berhak mendapatkan perlindungan terhadap perlakuan yang bersifat
diskriminatif itu
Perlindungan pemajuan penegakan dan pemenuhan hak asasi manusia adalah
tanggung jawab negara terutama pemerintah
Setiap orang wajib menghormati hak asasi manusia orang lain dalam tertib
kehidupan bermasyarakat berbangsa dan bernegara
Dalam menjalankan hak dan kebebasannya setiap orang wajib tunduk kepada
pembatasan yang ditetapkan dengan undang-undang dengan maksud semata-mata
untuk menjamin pengakuan serta penghormatan atas hak kebebasan orang lain dan
untuk memenuhi tuntutan yang adil sesuai dengan pertimbangan moral nilai-nilai
agama keamanan dan ketertiban umum dalam suatu masyarakat demokratis
Negara berdasar atas Ketuhanan Yang Maha Esa
Negara menjamin kemerdekaan tiap-tiap penduduk untuk memeluk agamanya
masing-masing dan untuk beribadat menurut agamanya dan kepercayaannya itu
Tiap-tiap warga negara berhak dan wajib ikut serta dalam usaha pertahanan dan
keamanan negara
Usaha pertahanan dan keamanan negara dilaksanakan melalui sistem pertahanan dan
keamanan rakyat semesta oleh Tentara Nasional Indonesia dan Kepolisian Negara
Republik Indonesia sebagai kekuatan utama dan rakyat sebagai kekuatan pendukung
Setiap warga negara berhak mendapat pendidikan
Setiap warga negara wajib mengikuti pendidikan dasar dan pemerintah wajib
membiayainya
Pemerintah mengusahakan dan menyelenggarakan satu sistem pendidikan nasional
yang meningkatkan keimanan dan ketakwaan serta akhlak mulia dalam rangka
mencerdaskan kehidupan bangsa yang diatur dengan undang-undang
Perekonomian disusun sebagai usaha bersama berdasar atas asas kekeluargaan
Cabang-cabang produksi yang penting bagi negara dan yang menguasai hajat hidup
orang banyak dikuasai oleh negara
Bumi dan air dan kekayaan alam yang terkandung di dalamnya dikuasai oleh negara
dan dipergunakan untuk sebesar-besar kemakmuran rakyat
Perekonomian nasional diselenggarakan berdasar atas demokrasi ekonomi dengan
prinsip kebersamaan efisiensi berkeadilan berkelanjutan berwawasan lingkungan
kemandirian serta dengan menjaga keseimbangan kemajuan dan kesatuan ekonomi
nasional
Fakir miskin dan anak-anak terlantar dipelihara oleh negara
Negara mengembangkan sistem jaminan sosial bagi seluruh rakyat dan
memberdayakan masyarakat yang lemah dan tidak mampu sesuai dengan martabat
kemanusiaan
Negara bertanggung jawab atas penyediaan fasilitas pelayanan kesehatan dan
fasilitas pelayanan umum yang layak
Bendera Negara Indonesia ialah Sang Merah Putih
Bahasa Negara ialah Bahasa Indonesia
Lambang Negara ialah Garuda Pancasila dengan semboyan Bhinneka Tunggal Ika
Lagu Kebangsaan ialah Indonesia Raya
Usul perubahan pasal-pasal Undang-Undang Dasar dapat diagendakan dalam sidang
Majelis Permusyawaratan Rakyat apabila diajukan oleh sekurang-kurangnya satu
pertiga dari jumlah anggota Majelis Permusyawaratan Rakyat
Setiap usul perubahan pasal-pasal Undang-Undang Dasar diajukan secara tertulis
dan ditunjukkan dengan jelas bagian yang diusulkan untuk diubah beserta
alasannya
Untuk mengubah pasal-pasal Undang-Undang Dasar sidang Majelis Permusyawaratan
Rakyat dihadiri sekurang-kurangnya dua pertiga dari jumlah anggota Majelis
Permusyawaratan Rakyat
Putusan untuk mengubah pasal-pasal Undang-Undang Dasar dilakukan dengan
persetujuan sekurang-kurangnya lima puluh persen ditambah satu anggota dari
seluruh anggota Majelis Permusyawaratan Rakyat
Khusus mengenai bentuk negara Kesatuan Republik Indonesia tidak dapat dilakukan
perubahan
"""

# Pasal-pasal terpilih UU Nomor 11 Tahun 2008 tentang Informasi dan Transaksi
# Elektronik (UU ITE).
PASAL_UU_ITE = """
Informasi Elektronik adalah satu atau sekumpulan data elektronik termasuk
tetapi tidak terbatas pada tulisan suara gambar peta rancangan foto surat
elektronik telegram teleks telecopy atau sejenisnya huruf tanda angka Kode
Akses simbol atau perforasi yang telah diolah yang memiliki arti atau dapat
dipahami oleh orang yang mampu memahaminya
Transaksi Elektronik adalah perbuatan hukum yang dilakukan dengan menggunakan
Komputer jaringan Komputer dan atau media elektronik lainnya
Teknologi Informasi adalah suatu teknik untuk mengumpulkan menyiapkan
menyimpan memproses mengumumkan menganalisis dan atau menyebarkan informasi
Dokumen Elektronik adalah setiap Informasi Elektronik yang dibuat diteruskan
dikirimkan diterima atau disimpan dalam bentuk analog digital elektromagnetik
optikal atau sejenisnya yang dapat dilihat ditampilkan dan atau didengar
melalui Komputer atau Sistem Elektronik
Sistem Elektronik adalah serangkaian perangkat dan prosedur elektronik yang
berfungsi mempersiapkan mengumpulkan mengolah menganalisis menyimpan
menampilkan mengumumkan mengirimkan dan atau menyebarkan Informasi Elektronik
Tanda Tangan Elektronik adalah tanda tangan yang terdiri atas Informasi
Elektronik yang dilekatkan terasosiasi atau terkait dengan Informasi Elektronik
lainnya yang digunakan sebagai alat verifikasi dan autentikasi
Komputer adalah alat untuk memproses data elektronik magnetik optik atau
sistem yang melaksanakan fungsi logika aritmatika dan penyimpanan
Akses adalah kegiatan melakukan interaksi dengan Sistem Elektronik yang berdiri
sendiri atau dalam jaringan
Kode Akses adalah angka huruf simbol karakter lainnya atau kombinasi di
antaranya yang merupakan kunci untuk dapat mengakses Komputer dan atau Sistem
Elektronik lainnya
Undang-Undang ini berlaku untuk setiap Orang yang melakukan perbuatan hukum
sebagaimana diatur dalam Undang-Undang ini baik yang berada di wilayah hukum
Indonesia maupun di luar wilayah hukum Indonesia yang memiliki akibat hukum di
wilayah hukum Indonesia dan atau di luar wilayah hukum Indonesia dan merugikan
kepentingan Indonesia
Pemanfaatan Teknologi Informasi dan Transaksi Elektronik dilaksanakan
berdasarkan asas kepastian hukum manfaat kehati-hatian iktikad baik dan
kebebasan memilih teknologi atau netral teknologi
Informasi Elektronik dan atau Dokumen Elektronik dan atau hasil cetaknya
merupakan alat bukti hukum yang sah
Setiap Orang dengan sengaja dan tanpa hak mendistribusikan dan atau
mentransmisikan dan atau membuat dapat diaksesnya Informasi Elektronik dan
atau Dokumen Elektronik yang memiliki muatan yang melanggar kesusilaan
Setiap Orang dengan sengaja dan tanpa hak mendistribusikan dan atau
mentransmisikan dan atau membuat dapat diaksesnya Informasi Elektronik dan
atau Dokumen Elektronik yang memiliki muatan perjudian
Setiap Orang dengan sengaja dan tanpa hak mendistribusikan dan atau
mentransmisikan dan atau membuat dapat diaksesnya Informasi Elektronik dan
atau Dokumen Elektronik yang memiliki muatan penghinaan dan atau pencemaran
nama baik
Setiap Orang dengan sengaja dan tanpa hak mendistribusikan dan atau
mentransmisikan dan atau membuat dapat diaksesnya Informasi Elektronik dan
atau Dokumen Elektronik yang memiliki muatan pemerasan dan atau pengancaman
Setiap Orang dengan sengaja dan tanpa hak menyebarkan berita bohong dan
menyesatkan yang mengakibatkan kerugian konsumen dalam Transaksi Elektronik
Setiap Orang dengan sengaja dan tanpa hak menyebarkan informasi yang ditujukan
untuk menimbulkan rasa kebencian atau permusuhan individu dan atau kelompok
masyarakat tertentu berdasarkan atas suku agama ras dan antargolongan
Setiap Orang dengan sengaja dan tanpa hak mengirimkan Informasi Elektronik dan
atau Dokumen Elektronik yang berisi ancaman kekerasan atau menakut-nakuti yang
ditujukan secara pribadi
Setiap Orang dengan sengaja dan tanpa hak atau melawan hukum mengakses
Komputer dan atau Sistem Elektronik milik Orang lain dengan cara apa pun
Setiap Orang dengan sengaja dan tanpa hak atau melawan hukum mengakses
Komputer dan atau Sistem Elektronik dengan cara apa pun dengan tujuan untuk
memperoleh Informasi Elektronik dan atau Dokumen Elektronik
Setiap Orang dengan sengaja dan tanpa hak atau melawan hukum mengakses
Komputer dan atau Sistem Elektronik dengan cara apa pun dengan melanggar
menerobos melampaui atau menjebol sistem pengamanan
Setiap Orang dengan sengaja dan tanpa hak atau melawan hukum melakukan
intersepsi atau penyadapan atas Informasi Elektronik dan atau Dokumen
Elektronik dalam suatu Komputer dan atau Sistem Elektronik tertentu milik Orang
lain
Setiap Orang dengan sengaja dan tanpa hak atau melawan hukum dengan cara apa
pun mengubah menambah mengurangi melakukan transmisi merusak menghilangkan
memindahkan menyembunyikan suatu Informasi Elektronik dan atau Dokumen
Elektronik milik Orang lain atau milik publik
Setiap Orang dengan sengaja dan tanpa hak atau melawan hukum melakukan
tindakan apa pun yang berakibat terganggunya Sistem Elektronik dan atau
mengakibatkan Sistem Elektronik menjadi tidak bekerja sebagaimana mestinya
Setiap Orang dengan sengaja dan tanpa hak atau melawan hukum melakukan
manipulasi penciptaan perubahan penghilangan pengrusakan Informasi Elektronik
dan atau Dokumen Elektronik dengan tujuan agar Informasi Elektronik dan atau
Dokumen Elektronik tersebut dianggap seolah-olah data yang otentik
Setiap Orang dengan sengaja dan tanpa hak atau melawan hukum melakukan
perbuatan yang dilarang yang mengakibatkan kerugian bagi Orang lain
Setiap Orang yang memenuhi unsur larangan penyebaran muatan yang melanggar
kesusilaan perjudian penghinaan pencemaran nama baik pemerasan atau pengancaman
dipidana dengan pidana penjara paling lama enam tahun dan atau denda paling
banyak satu miliar rupiah
Setiap Orang yang memenuhi unsur perbuatan mengakses Komputer secara melawan
hukum dipidana dengan pidana penjara paling lama enam tahun dan atau denda
paling banyak enam ratus juta rupiah
Setiap Orang yang memenuhi unsur perbuatan merusak Sistem Elektronik dipidana
dengan pidana penjara paling lama sepuluh tahun dan atau denda paling banyak
sepuluh miliar rupiah
"""

# Pasal-pasal terpilih UU Nomor 27 Tahun 2022 tentang Pelindungan Data Pribadi.
PASAL_UU_PDP = """
Data Pribadi adalah data tentang orang perseorangan yang teridentifikasi atau
dapat diidentifikasi secara tersendiri atau dikombinasi dengan informasi
lainnya baik secara langsung maupun tidak langsung melalui sistem elektronik
atau nonelektronik
Pelindungan Data Pribadi adalah keseluruhan upaya untuk melindungi Data Pribadi
dalam rangkaian pemrosesan Data Pribadi guna menjamin hak konstitusional subjek
Data Pribadi
Informasi adalah keterangan pernyataan gagasan dan tanda-tanda yang mengandung
nilai makna dan pesan baik data fakta maupun penjelasannya yang dapat dilihat
didengar dan dibaca yang disajikan dalam berbagai kemasan dan format sesuai
dengan perkembangan teknologi informasi dan komunikasi secara elektronik
ataupun nonelektronik
Pengendali Data Pribadi adalah setiap orang badan publik dan organisasi
internasional yang bertindak sendiri-sendiri atau bersama-sama dalam menentukan
tujuan dan melakukan kendali pemrosesan Data Pribadi
Prosesor Data Pribadi adalah setiap orang badan publik dan organisasi
internasional yang bertindak sendiri-sendiri atau bersama-sama dalam melakukan
pemrosesan Data Pribadi atas nama Pengendali Data Pribadi
Subjek Data Pribadi adalah orang perseorangan yang pada dirinya melekat Data
Pribadi
Setiap Orang adalah orang perseorangan atau korporasi
Korporasi adalah kumpulan orang dan atau kekayaan yang terorganisasi baik yang
berbadan hukum maupun tidak berbadan hukum
Undang-Undang ini berlaku untuk Setiap Orang Badan Publik dan Organisasi
Internasional yang melakukan perbuatan hukum sebagaimana diatur dalam
Undang-Undang ini baik yang berada di wilayah hukum Negara Republik Indonesia
maupun di luar wilayah hukum Negara Republik Indonesia yang memiliki akibat
hukum di wilayah hukum Negara Republik Indonesia dan atau bagi Subjek Data
Pribadi warga negara Indonesia di luar wilayah hukum Negara Republik Indonesia
Undang-Undang ini tidak berlaku untuk pemrosesan Data Pribadi oleh orang
perseorangan dalam kegiatan pribadi atau rumah tangga
Undang-Undang ini berasaskan pelindungan kepastian hukum kepentingan umum
kemanfaatan kehati-hatian keseimbangan pertanggungjawaban dan kerahasiaan
Data Pribadi yang bersifat spesifik meliputi data dan informasi kesehatan data
biometrik data genetika catatan kejahatan data anak data keuangan pribadi dan
atau data lainnya sesuai dengan ketentuan peraturan perundang-undangan
Data Pribadi yang bersifat umum meliputi nama lengkap jenis kelamin agama
status perkawinan dan atau Data Pribadi yang dikombinasikan untuk
mengidentifikasi seseorang
Subjek Data Pribadi berhak mendapatkan Informasi tentang kejelasan identitas
dasar kepentingan hukum tujuan permintaan dan penggunaan Data Pribadi dan
akuntabilitas pihak yang meminta Data Pribadi
Subjek Data Pribadi berhak melengkapi memperbarui dan atau memperbaiki
kesalahan dan atau ketidakakuratan Data Pribadi tentang dirinya sesuai dengan
tujuan pemrosesan Data Pribadi
Subjek Data Pribadi berhak mendapatkan akses dan memperoleh salinan Data
Pribadi tentang dirinya sesuai dengan ketentuan peraturan perundang-undangan
Subjek Data Pribadi berhak untuk mengakhiri pemrosesan menghapus dan atau
memusnahkan Data Pribadi tentang dirinya sesuai dengan ketentuan peraturan
perundang-undangan
Subjek Data Pribadi berhak menarik kembali persetujuan pemrosesan Data Pribadi
tentang dirinya yang telah diberikan kepada Pengendali Data Pribadi
Subjek Data Pribadi berhak menggugat dan menerima ganti rugi atas pelanggaran
pemrosesan Data Pribadi tentang dirinya sesuai dengan ketentuan peraturan
perundang-undangan
Pemrosesan Data Pribadi meliputi pemerolehan dan pengumpulan pengolahan dan
penganalisisan penyimpanan perbaikan dan pembaruan penampilan pengumuman
transfer penyebarluasan pengungkapan dan atau penghapusan atau pemusnahan
Pemrosesan Data Pribadi dilakukan dengan melindungi keamanan Data Pribadi dari
pengaksesan yang tidak sah pengungkapan yang tidak sah pengubahan yang tidak
sah perusakan dan atau penghilangan Data Pribadi
Data Pribadi dimusnahkan dan atau dihapus setelah masa retensi berakhir atau
berdasarkan permintaan Subjek Data Pribadi kecuali ditentukan lain oleh
peraturan perundang-undangan
Pengendali Data Pribadi wajib melindungi dan memastikan keamanan Data Pribadi
yang diprosesnya dengan melakukan penyusunan dan penerapan langkah teknis
operasional untuk melindungi Data Pribadi dari gangguan pemrosesan Data Pribadi
yang bertentangan dengan ketentuan peraturan perundang-undangan
Pengendali Data Pribadi wajib menjaga kerahasiaan Data Pribadi
Pengendali Data Pribadi wajib mencegah Data Pribadi diakses secara tidak sah
dengan menggunakan sistem keamanan terhadap Data Pribadi yang diproses dan
atau memproses Data Pribadi menggunakan sistem elektronik secara andal aman
dan bertanggung jawab
Setiap Orang dilarang secara melawan hukum memperoleh atau mengumpulkan Data
Pribadi yang bukan miliknya dengan maksud untuk menguntungkan diri sendiri atau
orang lain yang dapat mengakibatkan kerugian Subjek Data Pribadi
Setiap Orang dilarang secara melawan hukum mengungkapkan Data Pribadi yang
bukan miliknya
Setiap Orang dilarang secara melawan hukum menggunakan Data Pribadi yang bukan
miliknya
Setiap Orang dilarang membuat Data Pribadi palsu atau memalsukan Data Pribadi
dengan maksud untuk menguntungkan diri sendiri atau orang lain yang dapat
mengakibatkan kerugian bagi orang lain
Setiap Orang yang dengan sengaja dan melawan hukum memperoleh atau
mengumpulkan Data Pribadi yang bukan miliknya dengan maksud untuk menguntungkan
diri sendiri atau orang lain yang dapat mengakibatkan kerugian Subjek Data
Pribadi dipidana dengan pidana penjara paling lama lima tahun dan atau pidana
denda paling banyak lima miliar rupiah
Setiap Orang yang dengan sengaja dan melawan hukum mengungkapkan Data Pribadi
yang bukan miliknya dipidana dengan pidana penjara paling lama empat tahun dan
atau pidana denda paling banyak empat miliar rupiah
Setiap Orang yang dengan sengaja dan melawan hukum menggunakan Data Pribadi
yang bukan miliknya dipidana dengan pidana penjara paling lama lima tahun dan
atau pidana denda paling banyak lima miliar rupiah
Setiap Orang yang dengan sengaja membuat Data Pribadi palsu atau memalsukan
Data Pribadi dengan maksud untuk menguntungkan diri sendiri atau orang lain
yang dapat mengakibatkan kerugian bagi orang lain dipidana dengan pidana
penjara paling lama enam tahun dan atau pidana denda paling banyak enam miliar
rupiah
"""

# Daftar dokumen dengan urutan yang dipakai untuk membentuk corpus.
DOKUMEN = [
    ("Pancasila", PANCASILA),
    ("Proklamasi", PROKLAMASI),
    ("Pembukaan UUD 1945", PEMBUKAAN_UUD_1945),
    ("Pasal UUD 1945", PASAL_UUD_1945),
    ("Pasal UU ITE", PASAL_UU_ITE),
    ("Pasal UU PDP", PASAL_UU_PDP),
]


# ---------------------------------------------------------------------------
# Normalisasi dan pembentukan sampel
# ---------------------------------------------------------------------------
def normalize_az(text):
    """Ubah *text* menjadi string kapital yang hanya berisi huruf A-Z.

    Semua karakter selain A-Z (spasi, tanda baca, angka, baris baru) dibuang.
    """
    return "".join(ch for ch in text.upper() if "A" <= ch <= "Z")


def corpus_normal():
    """Gabungkan seluruh dokumen lalu normalkan menjadi satu string A-Z."""
    return "".join(normalize_az(teks) for _, teks in DOKUMEN)


def build_samples(sizes):
    """Buat sampel plaintext A-Z untuk tiap ukuran dari corpus dokumen.

    Sampel diambil dari awal corpus yang dinormalkan (konsisten dan
    reproducible), sehingga ukuran 50, 100, 500, ... merupakan prefix dari
    ukuran yang lebih besar.

    Args:
        sizes (iterable[int]): daftar ukuran yang diinginkan.

    Returns:
        dict: ``{ukuran: string_AZ_sepanjang_ukuran}``.
    """
    corpus = corpus_normal()
    if max(sizes) > len(corpus):
        raise ValueError(
            "ukuran sampel terbesar {} melebihi panjang corpus {}. "
            "Tambahkan dokumen pada modul sample_data.".format(
                max(sizes), len(corpus)
            )
        )
    return {size: corpus[:size] for size in sizes}


def build_sample_sets(sizes, samples_per_size=3):
    """Buat *beberapa* sampel plaintext berbeda untuk tiap ukuran.

    Untuk pengukuran waktu yang layak secara statistik, tiap ukuran diberi
    ``samples_per_size`` potongan **berbeda** dari corpus yang dinormalkan.
    Potongan disebar merata dari awal hingga akhir corpus (offset berbeda),
    sehingga untuk ukuran kecil pun sampelnya tidak tumpang-tindih.

    Args:
        sizes (iterable[int]): daftar ukuran yang diinginkan.
        samples_per_size (int): banyaknya sampel per ukuran (default 3).

    Returns:
        dict: ``{ukuran: [string_AZ_1, string_AZ_2, ...]}``.
    """
    corpus = corpus_normal()
    if max(sizes) > len(corpus):
        raise ValueError(
            "ukuran sampel terbesar {} melebihi panjang corpus {}. "
            "Tambahkan dokumen pada modul sample_data.".format(
                max(sizes), len(corpus)
            )
        )

    result = {}
    for size in sizes:
        max_start = len(corpus) - size
        samples = []
        for k in range(samples_per_size):
            if samples_per_size <= 1:
                start = 0
            else:
                start = round(k * max_start / (samples_per_size - 1))
            samples.append(corpus[start:start + size])
        result[size] = samples
    return result


if __name__ == "__main__":
    corpus = corpus_normal()
    print("Panjang corpus A-Z:", len(corpus))
    for nama, teks in DOKUMEN:
        print("  - {:20s}: {} huruf A-Z".format(
            nama, len(normalize_az(teks))))
