# pqc-scan teknik özet

Bu belge, projenin her parçasının **ne yaptığını ve neden öyle yapıldığını**
kısaca anlatır. Kavramlar için [kuantum rehberi](kuantum-rehberi.md);
ayrıntılı İngilizce tanım için [architecture.md](architecture.md).

## 1. Büyük resim

```
hedefler ──► tarayıcılar ──► gözlemler ──► sınıflandırıcı ──► bulgular ──► raporlar
            (tls, ssh,      "RSA-2048       algorithms.yaml     "RSA-2048 →     (konsol, JSON,
             code, files)    burada"                            VULNERABLE"      HTML, CBOM)
```

1. **Tarayıcılar** yalnızca *gördüklerini* not eder (gözlem). İyi/kötü
   kararı vermezler.
2. **Sınıflandırıcı** her gözlemi tek bir kural dosyasına bakarak
   değerlendirir ve risk sınıfı verir (bulgu).
3. **Motor** (`engine.py`) bu ikisini birleştirir: hedefleri paralel tarar,
   hataları toplar, aynı bulguyu bir kez yazar, en kötüden iyiye sıralar.
4. **Raporlayıcılar** sadece sonucu farklı biçimlerde yazar.

Neden böyle? Bir algoritmanın sınıfı değişirse (ör. NIST yeni bir karar
verirse) yalnızca `algorithms.yaml` güncellenir; tarayıcılara dokunulmaz.

## 2. Dosya dosya

| Dosya | Görevi |
| --- | --- |
| `models.py` | Ortak veri yapıları: Asset (varlık), Observation (gözlem), Finding (bulgu), ScanResult (sonuç), ScanConfig (ayarlar) |
| `classify.py` + `rules/algorithms.yaml` | Algoritma adı → risk sınıfı. 66 algoritma, yüzlerce takma adıyla |
| `engine.py` | Tarayıcıları paralel çalıştırır, hataları `errors` listesine yazar |
| `mosca.py` | Mosca aciliyet skoru ve varlık bazlı eşleme dosyası |
| `scanners/files.py` | Klasördeki sertifika/anahtar dosyaları |
| `scanners/certs.py` | Sertifika okuma (files ve tls ortak kullanır) |
| `scanners/tls*.py` | TLS taraması (3 dosya: adlar, sorgu, tarayıcı) |
| `scanners/ssh.py` | SSH taraması |
| `scanners/code*.py` + `rules/code_rules.yaml` | Kaynak kod taraması |
| `reporters/` | Konsol, JSON, HTML, CBOM çıktıları ve öneriler |
| `diff.py` | İki raporu karşılaştırır (yeni / çözülen bulgular) |
| `cli.py` | Komut satırı: `scan …`, `report`, `diff` |
| `action.yml` + `scripts/github-action.sh` | GitHub Action |
| `Dockerfile`, `.github/workflows/` | Docker imajı, CI ve yayın |

## 3. Risk sınıflandırması nasıl çalışır?

- Ad önce sadeleştirilir: `SHA-256`, `sha_256`, `SHA256` hepsi `sha256` olur.
- Kural dosyasında bulunmazsa sonuç `UNKNOWN`.
- Bulunursa ek kurallar denenir; **en kötüsü kazanır**. Ör. RSA varsayılan
  olarak `VULNERABLE`, ama "anahtar < 2048 bit" kuralı `BROKEN` der → sonuç
  `BROKEN`.
- **Bağlam önemlidir:** SHA-1 bir imzada `BROKEN`, HMAC içinde `WEAKENED`.
- Yoruma açık kararlar dosyada `judgement call, approved (D-13)` notuyla
  işaretli; hepsi 2026-11-06'da onaylandı. Yeni eklenen belirsiz bir karar
  onaylanana kadar `# TODO: doğrula` notu taşır.

## 4. Tarayıcılar

### files — dosyalar
- Dosyanın **içeriğine** bakar (uzantıya güvenmez): `-----BEGIN` ile
  başlayan her blok ayrı incelenir.
- Sertifikada üç şey raporlanır: açık anahtar, imza algoritması, imzadaki
  hash.
- Parolalı anahtarların **kilidi asla açılmaz**. OpenSSH anahtarında açık
  kısım kilitsiz durduğu için tip ve boyut yine okunur.
- Güvenlik: anahtarın içeriği hiçbir çıktıya yazılmaz; bunu doğrulayan
  testler var.

### tls — web sunucuları
- Hazır kütüphane yerine **kendi küçük sorgu kodumuz** (karar D-11). Sebep:
  hazır kütüphane hibrit kuantum gruplarını göremiyordu ve kurulumu ağırdı.
- Yöntem: sunucuya "şunları destekliyorum" diye bir liste gönderilir,
  sunucunun seçtiği not edilir, listeden çıkarılır, tekrar sorulur. Böylece
  desteklenen her şey ve seçim sırası öğrenilir. Genelde 20–40 kısa bağlantı.
- **Hibrit grup tespiti:** TLS 1.3 isteğinde bilerek hiç anahtar parçası
  gönderilmez; kurallar gereği sunucu "şu grubu kullan" (HelloRetryRequest)
  demek zorunda kalır. Böylece kuantum algoritmasını kendimiz hesaplamadan
  sunucunun X25519MLKEM768 destekleyip desteklemediği anlaşılır.
- El sıkışma tamamlanmaz, veri gönderilmez. Tek istisna: yalnızca TLS 1.3
  konuşan sunucuda sertifika şifreli geldiği için onu okumak üzere bir
  normal bağlantı kurulur.

### ssh — SSH sunucuları
- SSH sunucusu, şifreleme başlamadan önce desteklediği tüm algoritmaları
  açıkça yollar (KEXINIT). Araç sadece bu mesajı okur ve çıkar (karar D-5).
- Oturum açma, şifre deneme yok.

### code — kaynak kod
- Ek araç yok (karar D-12; Semgrep 72 MB ve Windows'ta çalışmıyor).
- **Python:** kod ağaç yapısına (AST) çevrilir; `import ... as ...`
  takma adları çözülür, böylece `r.generate_private_key(65537, 1024)` gibi
  bir çağrının gerçekte RSA-1024 olduğu anlaşılır.
- **Java/Kotlin, JS/TS, Go, C#, Rust:** yorumlar silinir, desen kuralları aranır
  (ör. `Cipher.getInstance("AES/ECB/...")` → AES + ECB). Anahtar boyutu ayrı
  satırda verilse bile (`kpg.initialize(2048)`) yakındaki satırlarda aranır.
- Bulguda **kodun kendisi değil**, sadece dosya, satır numarası ve API adı
  yer alır.
- Sınır: değer program çalışırken seçiliyorsa (ör. kullanıcı girişinden)
  görülemez.

## 5. Raporlar

| Biçim | Ne zaman? |
| --- | --- |
| `console` | Terminalde hızlıca bakmak için |
| `json` | Kaydetmek, karşılaştırmak (`diff`), başka araçlara vermek. Şeması: `docs/schema/` |
| `html` | Tek dosyalık sayfa; dışarıdan hiçbir şey yüklemez; süzme ve arama var |
| `cbom` | CycloneDX 1.6 standart envanteri; resmi şemaya karşı doğrulanıyor |
| `sarif` | GitHub'ın "Code scanning" ekranı gibi güvenlik panolarının okuduğu standart; yalnızca aksiyon gerektiren bulgular (UNKNOWN ve daha kötüsü) |

Her bulgu için bir **öneri** de üretilir; ayrıntılı yapılandırma örnekleri
[geçiş rehberinde](migration-guide.md).

## 6. Kalite ve güvenlik önlemleri

- **Testler:** ~340 test, kodun ~%97'sini kapsıyor. Testler internete hiç
  bağlanmaz: TLS ve SSH için bilgisayarın içinde sahte/gerçek test
  sunucuları kurulur. Test anahtarları her çalıştırmada yeniden üretilir,
  repoya özel anahtar konmaz.
- **Kontroller:** `ruff` (kod stili), `mypy --strict` (tip kontrolü),
  `pytest` (testler). GitHub'da her değişiklikte Python 3.11/3.12/3.13 ile,
  ayrıca Docker imajı ve GitHub Action'ın kendisi test edilir.
- **Sınırlar:** her ağ işlemi zaman aşımına uyar (varsayılan 5 sn), en fazla
  10 hedef aynı anda; bir hedefin hatası taramanın tamamını durdurmaz.
- **GitHub Action güvenliği:** kullanıcı girdileri komut satırına
  doğrudan yapıştırılmaz (komut enjeksiyonu engellenir).

## 7. Alınan kararlar (kısa)

| # | Karar |
| --- | --- |
| D-1 | Tarayıcı sadece gözlem üretir, sınıflandırma ayrı yerde |
| D-2, D-11 | TLS için kendi sorgu kodumuz; sslyze kullanılmaz |
| D-3 | Tanınmayan → `UNKNOWN`; çakışmada en kötü sınıf; bağlama göre karar |
| D-5 | SSH için ham bağlantıyla KEXINIT okunur |
| D-6, D-12 | Ağır bağımlılık yok; HTML/CBOM için opsiyonel `[report]`; Semgrep yok |
| D-7 | Mosca'da kuantum tarihi (z) için varsayılan yok |
| D-8 | Her komutta `--format` + `--out`; çıkış kodları 0/1/2/3 |
| D-9 | 3DES → BROKEN, AES-128 → WEAKENED, SHA-256 → PQ_SAFE |

## 8. Onaylanan yoruma açık sınıflandırmalar (D-13)

Aşağıdakiler mantıklı bir varsayımla eklenmişti ve 2026-11-06'da onaylandı:
TLS 1.2 → VULNERABLE, TLS 1.3 / SSH-2 → PQ_SAFE, SHA-256 → PQ_SAFE,
AES-192 / SHA3-224 / HMAC-SHA1 → WEAKENED, Blowfish / IDEA / CAST-128 →
BROKEN, SEED / Camellia-128 / ARIA-128 / UMAC-64 → WEAKENED, Camellia-256 /
ARIA-256 / UMAC-128 → PQ_SAFE, diffie-hellman-group14-sha1 → VULNERABLE,
FN-DSA → PQ_SAFE, X25519Kyber768Draft00 → HYBRID. Şu an onay bekleyen
sınıflandırma yok.
