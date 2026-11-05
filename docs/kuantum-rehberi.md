# Kuantum ve Kriptografi Rehberi

Bu belge, projede geçen teknik kavramları **sıfırdan** ve sade bir dille
anlatır. Proje ilerledikçe yeni kavramlar buraya eklenir.

Okuma sırası önerisi: 1 → 2 → 3 → 4. Sonraki bölümler ihtiyaç oldukça okunabilir.
En sondaki [sözlük](#sözlük) hızlı başvuru içindir.

---

## 1. Kriptografi neden var?

İnternette gönderdiğin her şey (şifre, kart numarası, mesaj) başkalarının
bilgisayarlarından geçer. Kriptografi üç şeyi sağlar:

| Amaç | Soru | Günlük örnek |
| --- | --- | --- |
| **Gizlilik** | Başkası okuyabilir mi? | Banka sitesindeki bilgilerin şifreli gitmesi |
| **Bütünlük** | Yolda değiştirildi mi? | İndirdiğin dosyanın bozulmadığından emin olmak |
| **Kimlik doğrulama** | Gerçekten o kişi/site mi? | Tarayıcıdaki kilit simgesi: "bu gerçekten bankam" |

Bunları yapmak için birkaç temel araç kullanılır. Bu araçlara **algoritma**
denir.

### 1.1 Anahtar

Kriptografide **anahtar**, kilidi açan şifredir; çok uzun, rastgele bir
sayıdır. Anahtarın uzunluğu **bit** ile ölçülür. 128 bitlik bir anahtar için
2¹²⁸ olasılık vardır — bu, evrendeki kum tanelerinden kat kat fazladır.
Tahmin ederek bulmak pratikte imkânsızdır.

### 1.2 Simetrik şifreleme — "tek anahtar"

Aynı anahtar hem kilitler hem açar. Hızlıdır; verinin kendisini şifrelemek için
kullanılır.

- Örnekler: **AES-128**, **AES-256**, ChaCha20
- Eskiler/zayıflar: **DES**, **3DES**, **RC4**

Sorun: İki taraf bu ortak anahtarı nasıl güvenle paylaşacak? Cevap: asimetrik
kriptografi.

### 1.3 Asimetrik (açık anahtarlı) kriptografi — "iki anahtar"

Her tarafın bir **açık anahtarı** (herkese verilebilir) ve bir **özel
anahtarı** (kimseye verilmez) vardır. Bir posta kutusu gibi düşün: herkes
kutuya mektup atabilir (açık anahtar), ama sadece anahtarı olan kutuyu açabilir
(özel anahtar).

İki ana kullanımı var:

- **Anahtar değişimi (key exchange):** İki taraf, internet üzerinden
  konuşarak, kimsenin bilmediği ortak bir simetrik anahtar üretir.
  Örnekler: **DH** (Diffie–Hellman), **ECDH**, **X25519**.
- **Dijital imza:** "Bu belgeyi ben imzaladım ve kimse değiştirmedi" demek.
  Örnekler: **RSA**, **ECDSA**, **Ed25519**, **DSA**.

Bu algoritmaların güvenliği, bazı matematik problemlerinin **çok zor**
olmasına dayanır:

| Algoritma ailesi | Dayandığı zor problem |
| --- | --- |
| RSA | Çok büyük bir sayıyı asal çarpanlarına ayırmak |
| DH, DSA | Ayrık logaritma problemi |
| ECDSA, ECDH, Ed25519, X25519 (eliptik eğri) | Eliptik eğri üzerinde ayrık logaritma |

> **Önemli:** Bu problemlerin hepsi kuantum bilgisayar için **kolaydır**.
> Projenin var olma sebebi tam olarak bu.

### 1.4 Hash (özet) fonksiyonu

Herhangi bir veriyi alıp sabit uzunlukta bir "parmak izi" üretir. Geri
döndürülemez; veri bir harf değişse parmak izi tamamen değişir.

- Güçlü: **SHA-256**, **SHA-384**, **SHA-512**, **SHA3**
- Kırık: **MD5**, **SHA-1** (iki farklı verinin aynı parmak izini vermesi —
  *çakışma* — pratikte üretilebiliyor)

### 1.5 MAC / HMAC

Bir hash'in gizli bir anahtarla birlikte kullanılması. "Bu mesaj, anahtarı
bilen biri tarafından gönderildi ve değişmedi" garantisi verir. HMAC, içindeki
hash'in çakışma zayıflığından çok daha az etkilenir; bu yüzden **SHA-1 imzada
kırık, HMAC-SHA1'de daha az riskli** sayılır. Projede algoritmanın *nerede
kullanıldığına* bakmamızın sebebi budur.

---

## 2. Kuantum bilgisayar nedir?

Normal bilgisayar **bit** kullanır: 0 ya da 1. Kuantum bilgisayar **kübit**
kullanır. Kübit, ölçülene kadar 0 ve 1'in bir karışımında
(**süperpozisyon**) durabilir ve kübitler birbirine **dolanık** olabilir.

Bunun pratik sonucu: Kuantum bilgisayar her şeyi hızlı yapmaz. Ama
**belirli** problem türlerinde, akıllıca tasarlanmış algoritmalarla, normal
bilgisayarın milyonlarca yılda yapacağını çok kısa sürede yapabilir.

Kriptografi için önemli olan iki kuantum algoritması var: **Shor** ve
**Grover**.

### 2.1 CRQC — "kriptografiyi kırabilecek kuantum bilgisayar"

*Cryptographically Relevant Quantum Computer.* RSA-2048 gibi gerçek bir
anahtarı kırabilecek büyüklükte ve hatasız çalışabilen kuantum bilgisayar.
Bugünkü makineler bunun çok gerisinde; ama 2025'te yayımlanan bir çalışma
(Gidney) RSA-2048'in yaklaşık bir milyon "gürültülü" kübitle bir haftadan kısa
sürede kırılabileceğini tahmin ederek eşiği ciddi şekilde aşağı çekti.
Ne zaman geleceği belirsizdir; bu yüzden araç bir tarih **varsaymaz**, tarihi
kullanıcı girer (bkz. [Mosca](#5-mosca-teoremi--ne-kadar-acil)).

---

## 3. Shor ve Grover: kuantum neyi kırar?

### 3.1 Shor algoritması — asimetrik kriptografinin sonu

Shor algoritması, **çarpanlara ayırma** ve **ayrık logaritma** problemlerini
hızlıca çözer. 1.3'teki tablodaki *bütün* zor problemler bunlardır.

Sonuç: Yeterince güçlü bir kuantum bilgisayar geldiğinde **RSA, DH, DSA,
ECDSA, ECDH, Ed25519, X25519 tamamen kırılır.** Anahtarı büyütmek (ör.
RSA-4096) çözüm değildir; sadece biraz daha fazla kübit gerektirir.

→ Projede bunlar **`VULNERABLE`** sınıfındadır.

### 3.2 Grover algoritması — simetrik kriptografiyi zayıflatır

Grover, "kaba kuvvet" aramayı hızlandırır: N olasılığı denemek yerine yaklaşık
√N deneme yeter. Bu, anahtarın etkili gücünü **yarıya** indirir:

| Algoritma | Bugünkü güç | Grover sonrası |
| --- | --- | --- |
| AES-128 | 128 bit | ~64 bit |
| AES-256 | 256 bit | ~128 bit (hâlâ çok güçlü) |
| SHA-256 (ters çevirme) | 256 bit | ~128 bit |

Pratikte Grover'ı çalıştırmak çok pahalıdır ve paralelleştirilmesi zordur; bu
yüzden bazı kurumlar (ör. NIST) AES-128'i hâlâ kabul edilebilir sayar. Bu proje
ihtiyatlı davranıp AES-128'i **`WEAKENED`**, AES-256'yı **`PQ_SAFE`** sayar.

Çözüm basit: anahtar uzunluğunu iki katına çıkar (AES-128 → AES-256).

### 3.3 "Şimdi topla, sonra çöz" (Harvest Now, Decrypt Later)

Kuantum bilgisayar henüz yok, o zaman neden şimdi endişeleniyoruz?

Çünkü bir saldırgan bugün şifreli trafiği **kaydedip saklayabilir** ve 10 yıl
sonra kuantum bilgisayar çıktığında çözebilir. Sağlık kaydı, devlet sırrı,
ticari sır gibi uzun süre gizli kalması gereken veriler **bugünden** risk
altındadır. Bu yüzden özellikle **anahtar değişiminin** hemen kuantuma dayanıklı
hale getirilmesi önerilir.

---

## 4. Post-kuantum kriptografi (PQC)

Kuantum bilgisayarın da kolayca çözemediği **farklı** matematik problemlerine
dayanan yeni algoritmalar. Normal bilgisayarlarda çalışırlar; özel donanım
gerekmez.

ABD'nin standart kurumu **NIST**, 2024'te ilk üç standardı yayımladı:

| Standart | Algoritma | Eski adı | Ne işe yarar | Dayandığı problem |
| --- | --- | --- | --- | --- |
| FIPS 203 | **ML-KEM** | Kyber | Anahtar paylaşımı (ECDH/DH yerine) | Kafes (lattice) |
| FIPS 204 | **ML-DSA** | Dilithium | Dijital imza (RSA/ECDSA yerine) | Kafes (lattice) |
| FIPS 205 | **SLH-DSA** | SPHINCS+ | Dijital imza, yedek | Yalnızca hash fonksiyonları |

- **KEM (Key Encapsulation Mechanism):** "Anahtar kapsülleme". Bir taraf
  rastgele bir anahtar üretip karşı tarafın açık anahtarıyla bir "kapsül"e
  koyar; sadece karşı taraf açabilir. Anahtar değişiminin PQC'deki karşılığı.
- **Kafes (lattice) problemi:** Çok boyutlu bir nokta ızgarasında, gürültü
  eklenmiş bir noktaya en yakın ızgara noktasını bulmak. Hem normal hem
  kuantum bilgisayar için zor kabul edilir.
- Sayılar (ML-KEM-**768**, ML-DSA-**65**) güvenlik seviyesini belirtir;
  büyüdükçe güvenlik ve boyut artar.

→ Projede bunlar **`PQ_SAFE`** sınıfındadır.

### 4.1 Hibrit kriptografi

Yeni algoritmalar henüz eskiler kadar uzun yıllar test edilmedi. Bu yüzden
geçiş döneminde **eski + yeni birlikte** kullanılır: saldırganın ikisini
birden kırması gerekir.

- **X25519MLKEM768:** X25519 (klasik) + ML-KEM-768 (PQ). Chrome, Firefox ve
  Cloudflare gibi büyük oyuncular TLS'te bunu varsayılan olarak kullanıyor.
- **mlkem768x25519-sha256:** SSH'taki karşılığı (OpenSSH 10'da varsayılan).
- **sntrup761x25519-sha512:** SSH'taki daha eski hibrit seçenek (OpenSSH 9'da varsayılan).

→ Projede bunlar **`HYBRID`** sınıfındadır ve **iyi** bir durumu gösterir.

---

## 5. Mosca teoremi — "ne kadar acil?"

Michele Mosca'nın basit formülü:

```
x + y > z   →   risk var
```

- **x:** Verinin kaç yıl gizli kalması gerekiyor? (ör. sağlık verisi: 25 yıl)
- **y:** Sistemi PQC'ye geçirmek kaç yıl sürer? (ör. 5 yıl)
- **z:** CRQC'nin gelmesine kaç yıl var? (tahmin; ör. 15 yıl)

Örnek: 25 + 5 = 30 > 15 → **çok geç kalınmış**, veri şimdiden risk altında
(bkz. 3.3). Araç üç değerin de kullanıcı tarafından girilmesini ister; z için
kendi tahminini dayatmaz.

---

## 6. Projenin baktığı yerler

### 6.1 TLS — web sitelerinin kilidi

**TLS**, tarayıcıdaki `https://` ve kilit simgesinin arkasındaki protokoldür.
Bağlantı kurulurken iki taraf bir **el sıkışma (handshake)** yapar:

1. **ClientHello** — İstemci (tarayıcı) "merhaba" der ve desteklediklerini
   listeler: TLS sürümleri, şifre takımları, anahtar değişim grupları.
2. **ServerHello** — Sunucu bu listeden seçimini yapıp söyler.
3. Sunucu **sertifikasını** gönderir (kimlik kartı gibi).
4. Anahtar değişimi yapılır, şifreli konuşma başlar.

Kavramlar:

- **TLS sürümü:** TLS 1.0 ve 1.1 eski ve kırık (`BROKEN`); TLS 1.2 ve 1.3
  güncel. SSLv2/v3 çok eski ve kırık.
- **Şifre takımı (cipher suite):** Bir bağlantıda kullanılacak algoritmaların
  paket adı. Ör. `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` =
  anahtar değişimi **ECDHE** + kimlik **RSA** + şifreleme **AES-128-GCM** +
  hash **SHA-256**. Araç bu ismi parçalarına ayırıp her parçayı ayrı
  değerlendirir.
- **Grup (group):** Anahtar değişiminde kullanılan matematiksel yapı.
  Ör. `x25519`, `secp256r1`, hibrit `X25519MLKEM768`.
- **Sertifika:** Sitenin kimliğini kanıtlayan, bir otorite tarafından
  imzalanmış belge. İçinde sitenin **açık anahtarı** (ör. RSA-2048) ve
  **imza algoritması** (ör. `sha256WithRSAEncryption`) bulunur. İkisi de
  kuantuma karşı savunmasız olabilir.

#### "Prob" (sorgu) ne demek?

Bir sunucuya "şu grubu destekliyor musun?" diye sormak için ona özel olarak
hazırlanmış bir **ClientHello** gönderip cevabına bakmaktır. Kapıyı çalıp
"içeride X var mı?" diye sormak gibi; içeri girilmez. Araç cevabı okuduktan
sonra bağlantıyı **kapatır**, el sıkışmayı tamamlamaz, oturum açmaz.

Neden kendi sorgumuzu yazıyoruz? Hazır TLS tarama kütüphanesi (`sslyze`)
eski bir altyapı kullandığı için hibrit PQ gruplarını soramıyor, üstelik
kurulumu ağır. Bu yüzden (karar D-11) sürümleri, şifre takımlarını ve
grupları soran sorgu kodunu tamamen kendimiz yazdık. Aynı soruyu, her
seferinde cevap olarak gelen seçeneği listeden çıkararak tekrar sorarız;
böylece sunucunun desteklediği her şeyi ve **tercih sırasını** öğreniriz.

### 6.2 SSH — sunuculara uzaktan bağlanma

**SSH**, sistem yöneticilerinin sunuculara komut satırından bağlandığı
protokoldür. Bağlantının en başında iki taraf **KEXINIT** adlı bir mesajla
desteklediği algoritmaların listesini **şifresiz** olarak gönderir:

- **KEX (key exchange):** Anahtar değişim yöntemleri
  (ör. `curve25519-sha256`, hibrit `mlkem768x25519-sha256`)
- **Host key:** Sunucunun kimlik anahtarı (ör. `ssh-ed25519`, `rsa-sha2-512`)

Araç sadece bu ilk listeyi okur ve bağlantıyı kapatır; kullanıcı adı veya
parola **hiç** gönderilmez.

### 6.3 Kod ve dosyalar

- **PEM:** `-----BEGIN CERTIFICATE-----` gibi satırlarla başlayan, metin
  biçimindeki sertifika/anahtar dosyası.
- **DER:** Aynı içeriğin ikili (binary) biçimi.
- **`.pub` dosyası:** SSH açık anahtarı. `authorized_keys` (bir sunucuya
  kimlerin girebileceği) ve `known_hosts` (bilgisayarının daha önce gördüğü
  sunucuların anahtarları) da aynı türden satırlar içerir.
- **CSR (sertifika imzalama isteği):** Bir sertifika otoritesine "bu açık
  anahtar için bana sertifika ver" diye gönderilen, sahibinin kendi anahtarıyla
  imzaladığı başvuru dosyası.
- **Kendinden imzalı (self-signed) sertifika:** Bir otorite yerine kendi
  anahtarıyla imzalanmış sertifika. Test ortamlarında yaygındır; burada imzayı
  atan anahtar sertifikanın kendi anahtarı olduğu için araç imzanın boyutunu
  da bilir.
- **OID:** Algoritmaların noktalı sayılardan oluşan resmi kimlik numarası
  (ör. `1.2.840.113549.1.1.11` = "SHA-256 ile RSA imzası"). Sertifikaların
  içinde algoritma adı değil OID yazar; araç OID'yi ada çevirir. Tanımadığı
  bir OID'yi olduğu gibi raporlar (`UNKNOWN`).
- **Parolalı (şifreli) özel anahtar:** Özel anahtar dosyası bir parolayla
  kilitlenmiş olabilir. Araç **asla parola denemez ve kilidi açmaz**. OpenSSH
  biçiminde açık anahtar kısmı kilitsiz durduğu için tip ve boyut yine
  okunabilir; PKCS#8 biçiminde ise tip görünmez, bulgu `UNKNOWN` olur.
- **Kod taraması:** Kaynak kodda `RSA.generate(2048)` gibi kripto
  kullanımlarını bulmak. Bunun için **Semgrep** (kod içinde desen arayan araç)
  ve Python için **AST** (kodu ağaç yapısına çevirip inceleme) kullanılır.

---

## 7. Projenin kendi terimleri

### 7.1 Risk sınıfları

Kötüden iyiye:

| Sınıf | Basitçe | Örnek |
| --- | --- | --- |
| `BROKEN` | Kuantuma bile gerek yok, bugün zayıf | MD5, SHA-1 imza, RC4, 3DES, TLS 1.0, RSA-1024 |
| `VULNERABLE` | Kuantum gelince kırılır (Shor) | RSA-2048, ECDSA, X25519 |
| `WEAKENED` | Kuantum gelince zayıflar (Grover) | AES-128 |
| `UNKNOWN` | Aracın tanımadığı algoritma; insan bakmalı | — |
| `HYBRID` | Klasik + PQ birlikte; iyi durum | X25519MLKEM768 |
| `PQ_SAFE` | Kuantuma dayanıklı | ML-KEM, ML-DSA, AES-256, SHA-384 |

Bir şeye birden çok kural uyuyorsa **en kötüsü** geçerlidir. Ör. RSA-1024 hem
"RSA → VULNERABLE" hem "1024 bit → BROKEN" kuralına uyar; sonuç `BROKEN`.

### 7.2 Gözlem (Observation) ve Bulgu (Finding)

Aracın içinde iş bölümü şöyle:

1. **Tarayıcı** sadece gördüğünü not eder: "`example.com:443` sertifikasında
   RSA-2048 var." Bu bir **gözlem**dir; iyi mi kötü mü olduğuna karar vermez.
2. **Sınıflandırıcı** (`classify`) bu gözlemi kural listesine bakarak
   değerlendirir: "RSA-2048 → `VULNERABLE`." Sonuç bir **bulgu**dur.

Böylece "neyin riskli olduğu" bilgisi tek bir dosyada (`algorithms.yaml`)
durur. Yarın bir algoritmanın sınıfı değişirse sadece o dosya güncellenir,
dört tarayıcıya tek tek dokunmak gerekmez.

### 7.3 CBOM

**Cryptographic Bill of Materials** — "kriptografik malzeme listesi". Bir
yemeğin içindekiler listesi gibi: hangi sistemde hangi algoritmalar var.
**CycloneDX** bu listenin standart dosya biçimidir; böylece başka araçlar da
raporu okuyabilir.

### 7.4 Pasif tarama

Sadece sunucunun herkese açık olarak söylediklerini dinlemek. Saldırı yok,
parola denemesi yok, oturum açma yok. Yine de **yalnızca sahibi olduğun veya
yazılı izin aldığın** sistemleri tara.

### 7.5 Raporlar, CI kapısı ve çıkış kodları

- **Konsol raporu:** Terminalde renkli tablo. En kötü bulgu en üstte.
- **JSON raporu:** Aynı bilgilerin programların okuyabileceği hâli.
  `pqc-scan report rapor.json` ile sonradan tekrar tabloya çevrilebilir.
  Biçimi bir **JSON şeması** ile tanımlıdır (şema: "bu dosyada hangi alanlar
  olur, hangi tipte olur" diyen kural dosyası).
- **CI (sürekli entegrasyon):** Kod her değiştiğinde testleri otomatik
  çalıştıran sistem (ör. GitHub Actions). `--fail-on VULNERABLE` dersen,
  araç `VULNERABLE` veya daha kötü bir bulgu gördüğünde **çıkış kodu 1** ile
  biter ve CI işi "kırmızı" olur — yani yeni bir zayıf anahtar fark
  edilmeden içeri giremez.
- **Çıkış kodu:** Bir programın bittiğinde işletim sistemine bıraktığı sayı.
  `0` her şey yolunda · `1` `--fail-on` eşiği aşıldı · `2` komut yanlış
  kullanıldı · `3` hiçbir hedef taranamadı.

---

## Sözlük

| Terim | Kısa açıklama | Bölüm |
| --- | --- | --- |
| 3DES | Eski simetrik şifre; bugün zayıf | 1.2 |
| AES | Standart simetrik şifre (128/192/256 bit) | 1.2 |
| AST | Kodu ağaç yapısında inceleme yöntemi | 6.3 |
| Açık / özel anahtar | Paylaşılabilen / gizli tutulan anahtar çifti | 1.3 |
| CBOM | Kriptografik malzeme listesi | 7.3 |
| CI / çıkış kodu | Otomatik test sistemi / programın bitiş sayısı | 7.5 |
| Cipher suite | Bir TLS bağlantısındaki algoritma paketi | 6.1 |
| ClientHello / ServerHello | TLS el sıkışmasının ilk iki mesajı | 6.1 |
| CRQC | Kriptografiyi kırabilecek güçte kuantum bilgisayar | 2.1 |
| CSR | Sertifika imzalama isteği | 6.3 |
| DH / ECDH | Klasik anahtar değişim yöntemleri | 1.3 |
| ECDSA / Ed25519 | Eliptik eğri tabanlı imzalar | 1.3 |
| Grover | Kaba kuvveti hızlandıran kuantum algoritması | 3.2 |
| Grup (TLS) | Anahtar değişiminde kullanılan yapı | 6.1 |
| Hash | Verinin geri döndürülemez parmak izi | 1.4 |
| Hibrit | Klasik + PQ algoritmanın birlikte kullanımı | 4.1 |
| HMAC | Anahtarlı hash; mesaj doğrulama | 1.5 |
| HNDL | "Şimdi topla, sonra çöz" saldırısı | 3.3 |
| JSON şeması | JSON dosyasının biçim kuralları | 7.5 |
| KEM | Anahtar kapsülleme mekanizması | 4 |
| KEX / KEXINIT | SSH anahtar değişimi / ilk algoritma listesi mesajı | 6.2 |
| Kafes (lattice) | ML-KEM ve ML-DSA'nın dayandığı zor problem | 4 |
| Kendinden imzalı sertifika | Kendi anahtarıyla imzalanmış sertifika | 6.3 |
| Kübit | Kuantum bilgisayarın temel birimi | 2 |
| ML-KEM / ML-DSA / SLH-DSA | NIST'in PQC standartları | 4 |
| Mosca teoremi | Aciliyet formülü: x + y > z | 5 |
| OID | Algoritmanın resmi sayısal kimliği | 6.3 |
| Parolalı özel anahtar | Parolayla kilitlenmiş anahtar dosyası; araç kilidi açmaz | 6.3 |
| PEM / DER | Sertifika/anahtar dosya biçimleri | 6.3 |
| PQC | Post-kuantum kriptografi | 4 |
| Prob (sorgu) | Sunucuya destek sorusu sorup cevabı okumak | 6.1 |
| RSA | En yaygın klasik açık anahtar algoritması | 1.3 |
| Shor | Asimetrik kriptografiyi kıran kuantum algoritması | 3.1 |
| Sertifika | Bir sitenin imzalı kimlik belgesi | 6.1 |
| SSH | Sunuculara güvenli uzaktan bağlantı protokolü | 6.2 |
| TLS | HTTPS'in arkasındaki güvenli bağlantı protokolü | 6.1 |
| X25519 | Modern klasik anahtar değişimi | 1.3 |
