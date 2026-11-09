# pqc-scan kullanım kılavuzu

Bu kılavuz, aracı hiç teknik bilgi olmadan kullanabilmen için yazıldı.
Kavramların açıklaması için [kuantum rehberi](kuantum-rehberi.md), aracın
içinin nasıl çalıştığı için [teknik özet](teknik-ozet.md).

> ⚠️ **Yalnızca sahibi olduğun veya yazılı izin aldığın sistemleri tara.**
> Araç saldırı yapmaz, şifre denemez, oturum açmaz; ama başkasının
> sunucusunu izinsiz taramak yine de doğru değildir.

## 1. Ne işe yarar?

pqc-scan, bir projede ve sunucularda **kuantum bilgisayarlara karşı zayıf
kalacak şifreleme** var mı diye bakar ve sana bir liste verir: nerede, hangi
algoritma, ne kadar riskli ve ne yapmalı.

## 2. Kurulum (bir kere)

Bilgisayarında Python 3.11 veya daha yenisi olmalı. Terminali açıp:

```bash
pip install "pqc-readiness-scanner[report]"
```

Paketin PyPI'deki adı `pqc-readiness-scanner`, terminalde yazılan komut ise
`pqc-scan`. PyPI'deki ilk yayından önce GitHub'dan kurmak için:
`pip install "pqc-readiness-scanner[report] @ git+https://github.com/YusufTaha-Kurt/pqc-scan"`. Kurulduğunu kontrol et:

```bash
pqc-scan --version
```

Docker kullanıyorsan kurulum gerekmez:

```bash
docker build -t pqc-scan .
docker run --rm pqc-scan --help
```

## 3. En sık kullanılan komutlar

| Ne yapmak istiyorsun? | Komut |
| --- | --- |
| Bir klasördeki sertifika/anahtar dosyalarını bul | `pqc-scan scan files ./proje` |
| Kaynak koddaki kripto kullanımını bul | `pqc-scan scan code ./proje` |
| Bir web sitesinin TLS ayarlarını incele | `pqc-scan scan tls site.com` |
| Bir SSH sunucusunu incele | `pqc-scan scan ssh sunucu.com` |
| Hepsini tek raporda | `pqc-scan scan all --path ./proje --tls site.com --ssh sunucu.com` |

Port numarası farklıysa sonuna yaz: `site.com:8443`, `sunucu.com:2222`.

## 4. Sonucu okumak

Ekranda önce bir **özet** tablosu çıkar: her risk sınıfında kaç bulgu var.
Sonra **bulgular** (en kötüsü en üstte) ve **öneriler** gelir.

| Sınıf | Ne demek? | Ne yapmalı? |
| --- | --- | --- |
| `BROKEN` | Bugün bile zayıf | **Hemen** düzelt |
| `VULNERABLE` | Kuantum bilgisayar gelince kırılır | Geçiş planına al |
| `WEAKENED` | Kuantumla güvenlik payı azalır | Fırsat buldukça güçlendir |
| `UNKNOWN` | Araç tanımadı | Bir uzmana sor |
| `HYBRID` | Klasik + kuantuma dayanıklı | İyi durum |
| `PQ_SAFE` | Kuantuma dayanıklı | İyi durum |

"Öneriler" (Recommendations) tablosu her sorun için ne yapılacağını tek
cümleyle söyler. Daha ayrıntılı örnekler: [geçiş rehberi](migration-guide.md).

## 5. Raporu dosyaya kaydetmek

```bash
pqc-scan scan all --path ./proje --format html --out rapor.html   # tarayıcıda aç
pqc-scan scan all --path ./proje --format json --out rapor.json   # sonra tekrar kullanmak için
pqc-scan scan all --path ./proje --format cbom --out cbom.json    # standart envanter (CycloneDX)
pqc-scan scan all --path ./proje --format sarif --out sonuc.sarif # güvenlik panoları (GitHub Code scanning)
```

HTML raporda risk sınıfına göre süzme ve arama kutusu vardır. Kaydedilmiş
JSON raporu sonradan başka biçime çevirebilirsin:

```bash
pqc-scan report rapor.json --format html --out rapor.html
```

## 6. Birçok hedefi bir dosyadan vermek

`hedefler.txt`:

```
# satır başına bir hedef; # ile başlayan satırlar yorumdur
tls://site.com
tls://mail.site.com:465
ssh://sunucu.com:22
path:./proje
```

```bash
pqc-scan scan all --targets hedefler.txt --format html --out rapor.html
```

## 7. Aciliyet skoru (Mosca) — isteğe bağlı

Üç sayı verirsin (yıl olarak):

- `--mosca-x`: bu verinin kaç yıl gizli kalması gerekiyor?
- `--mosca-y`: sistemi değiştirmek kaç yıl sürer?
- `--mosca-z`: sence kuantum bilgisayar kaç yıl sonra hazır olur?

x + y, z'den büyükse bulgu "at risk" (tehlikede) olarak işaretlenir. Araç
z için kendi tahminini kullanmaz; sen vermezsen skor hesaplanmaz.

```bash
pqc-scan scan all --path ./proje --mosca-x 10 --mosca-y 5 --mosca-z 12
```

Sistemlere farklı değer vermek için bir dosya kullan (`mosca.yaml`):

```yaml
default: {x: 5, y: 3}
assets:
  - match: "tls://*.banka.example:*"
    x: 25
  - match: "src/odeme/*"
    x: 10
```

```bash
pqc-scan scan all --path ./proje --mosca-file mosca.yaml --mosca-z 12
```

## 8. GitHub'da otomatik kontrol

Projene `.github/workflows/pqc-scan.yml` dosyasını ekle:

```yaml
name: pqc-scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: {fetch-depth: 0}
      - uses: YusufTaha-Kurt/pqc-scan@v0.3.0
        with:
          path: .
          fail-on: BROKEN
```

Her değişiklikte tarama yapılır, rapor "Artifacts" bölümüne konur.
Bulguları deponun **Security → Code scanning** sekmesinde görmek için
`with:` altına `upload-sarif: true` ekle ve iş akışının en üstüne
`permissions: {contents: read, security-events: write}` yaz. Bir pull
request **yeni** bir `BROKEN` sorun eklerse kontrol kırmızı olur; projede
zaten var olan eski sorunlar PR'ı engellemez. İki raporu elle karşılaştırmak
için:

```bash
pqc-scan diff eski.json yeni.json
```

## 9. Çıkış kodları (otomasyon için)

| Kod | Anlamı |
| --- | --- |
| 0 | Tarama bitti, sorun yok (veya `--fail-on` verilmedi) |
| 1 | `--fail-on` ile verilen eşik aşıldı |
| 2 | Komut yanlış yazıldı |
| 3 | Hiçbir hedef taranamadı (ör. sunucuya ulaşılamadı) |

## 10. Sık karşılaşılan durumlar

- **"connection_refused" / "timeout":** Sunucuya ulaşılamadı. Adresi ve
  portu kontrol et; yavaş ağlarda `--timeout 10` dene.
- **"no TLS handshake response":** O portta TLS çalışmıyor.
- **"encrypted private key" → `UNKNOWN`:** Parolalı bir anahtar dosyası;
  araç parolayı denemez, bu yüzden tipini göremez. Elle kontrol et.
- **Test klasörleri gürültü yapıyor:** `--exclude tests/fixtures` ile atla.
- **HTML/CBOM için "needs extra packages":** `pip install "pqc-readiness-scanner[report]"`.

## 11. Yayınlama (proje sahibi için, bir kerelik)

Paketin PyPI adı **`pqc-readiness-scanner`** (`pqc-scan` adı PyPI'de başka bir
projeye ait). Şifre veya token gerekmez: PyPI'ye "bu GitHub deposundan gelen
yayına güven" denir (trusted publishing).

1. **PyPI:** https://pypi.org hesabında iki adımlı doğrulamayı aç →
   *Your account → Publishing* → "Add a new pending publisher" → **GitHub**:
   - PyPI Project Name: `pqc-readiness-scanner`
   - Owner: `YusufTaha-Kurt`
   - Repository name: `pqc-scan`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
2. **GitHub ortamı:** depo → *Settings → Environments → New environment* →
   `pypi`. İstersen "Required reviewers"a kendini ekle (her yayında onay ister).
3. **Yayın:** depo → *Releases → Draft a new release* → "Choose a tag"a
   `v0.3.0` yazıp *Create new tag* (hedef: `master`) → *Publish release*.
   Bu, *Actions* sekmesindeki "Release" işini başlatır: testler, etiket/sürüm
   kontrolü, PyPI yüklemesi ve `ghcr.io/yusuftaha-kurt/pqc-scan` Docker imajı.
4. **Kontrol:** https://pypi.org/project/pqc-readiness-scanner/ açılıyorsa
   tamam. Docker imajı ilk seferde gizli oluşur; herkese açmak için GitHub
   profilinde *Packages → pqc-scan → Package settings → Change visibility →
   Public*.

Sonraki sürümlerde: `src/pqc_scan/__init__.py` içindeki sürümü ve
`CHANGELOG.md`'yi güncelle, birleştir, aynı sürüm numarasıyla yeni bir
release oluştur (ör. `v0.3.1`).
