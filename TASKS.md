# Görev Listesi — pqc-scan

Bu dosya `CLAUDE.md` §10'daki yol haritasının uygulanabilir görevlere bölünmüş
halidir. Sistem tanımı: [`docs/architecture.md`](docs/architecture.md).

Durum işaretleri: `[ ]` yapılacak · `[~]` devam ediyor · `[x]` tamamlandı

Her görev ayrı bir branch/PR olarak düşünülmüştür (önerilen branch adı parantez
içinde). Görev tamamlandığında burada ve `CLAUDE.md` §10'da işaretlenir.
Yeni oturumda devam etme kuralları: `CLAUDE.md` §12.

---

## Şu anki durum

> Her oturumun sonunda bu bölümü güncelle.

**Son güncelleme:** 2026-11-06

**Yol haritasının tamamı (v0.1–v0.3) bitti.** Sürüm 0.3.0. 341 test
(Python 3.11 ve 3.13), kapsama %97. Tüm komutlar çalışıyor:
`scan files|code|tls|ssh|all`, `report`, `diff`; biçimler
`console|json|html|cbom`. GitHub Action, Docker imajı, yayın iş akışı,
öğren not defterleri ve Türkçe kullanım kılavuzu + teknik özet hazır.

**Kullanıcıyı bekleyenler:**
1. Branch `claude/nice-gates-b8wil6`'yı PR ile `master`'a birleştirmek.
2. İlk yayın: PyPI trusted publisher + GitHub `pypi` ortamı, sonra
   `git tag v0.3.0 && git push origin v0.3.0`
   (`docs/kullanim-kilavuzu.md` §11).
3. `# TODO: doğrula` notlu sınıflandırmaların onayı
   (`docs/teknik-ozet.md` §8'de liste).

**Sonraki fikirler (yol haritasında yok, isteğe bağlı):**
- Gerçek OpenSSL ≥ 3.5 sunucusuyla hibrit grup uçtan uca testi (CI'da
  `openssl s_server` ile).
- Kod tarayıcısına C#/.NET ve Rust kuralları.
- ML-DSA sertifikaları yaygınlaşınca CBOM'a sertifika ayrıntıları
  (subject/issuer, geçerlilik tarihleri).
- SARIF çıktısı (GitHub "code scanning" ekranında göstermek için).

### Bilinen notlar

- Geliştirme Python 3.11 venv ile yapıldı; testler 3.13'te de geçiyor.
- CI (`.github/workflows/ci.yml`) yalnızca `master`'a push ve PR'larda çalışır;
  GitHub'da henüz hiç çalıştırılmadı.
- `cryptography` 50: DH/DSA sınıflarına erişim kullanımdan kaldırma uyarısı
  veriyor; `files.py` anahtar tiplerini içe aktarma anında uyarıyı bastırarak
  ve `getattr` ile yüklüyor (ileride kaldırılırlarsa da çalışır). OpenSSL artık
  SHA-1 imza üretmiyor; SHA-1 sertifika testi OID'si değiştirilmiş bir
  sertifikayla yapılıyor. Şifreli OpenSSH anahtarı üretmek `bcrypt` istediği
  için test anahtarı elle kuruluyor (`conftest.encrypted_openssh_private`).
- `files` tarayıcısı `AssetKind.CERTIFICATE_REQUEST` ekledi (CSR'lar için).
- `typer` 0.27 artık `click`'e bağımlı değil (içine gömülü); CLI'de yalnızca
  `typer.BadParameter` / `typer.Exit` kullanılır, `import click` yapılmaz.
- Raporlayıcı snapshot'ları `tests/snapshots/`; bilerek değişiklik yapınca
  `PQC_UPDATE_SNAPSHOTS=1 pytest` ile güncelle ve farkı gözden geçir. JSON
  şeması `docs/schema/scan-result.schema.json` da aynı yolla güncellenir.
- TLS testleri iki tür yerel sunucu kullanır (`tests/conftest.py`:
  `LocalServer`, `local_server` fixture'ı): Python `ssl` ile gerçek OpenSSL
  sunucusu ve `test_scanner_tls.py` içindeki betikli sahte sunucu. Bu
  ortamdaki OpenSSL 3.0 ML-KEM bilmediği için hibrit grup yolu sahte
  sunucuyla test edilir; OpenSSL ≥ 3.5 olan bir makinede gerçek sunucuyla
  da denenebilir.
- `algorithms.yaml`'a TLS için eklenen ve doğrulanması gerekenler:
  IDEA → BROKEN, SEED → WEAKENED, Camellia-128 / ARIA-128 → WEAKENED,
  Camellia-256 / ARIA-256 → PQ_SAFE (hepsi `# TODO: doğrula`). Kesin
  olanlar: export şifreleri ve `anon` kimlik doğrulama → BROKEN.
- Düzeltilen hata: Mosca skorlu JSON raporu geri okunamıyordu
  (`margin`/`at_risk` hesaplanan alanları reddediliyordu).
- `algorithms.yaml` içindeki `# TODO: doğrula` notları kullanıcıya bildirildi,
  cevap bekleniyor: TLS 1.2 → VULNERABLE, TLS 1.3 → PQ_SAFE, SHA-256 → PQ_SAFE,
  AES-192 / SHA3-224 / HMAC-SHA1 → WEAKENED, Blowfish → BROKEN,
  diffie-hellman-group14-sha1 → VULNERABLE, FN-DSA → PQ_SAFE,
  X25519Kyber768Draft00 → HYBRID.

### Oturum günlüğü

- **2026-11-04** — Proje analizi; görev listesi ve sistem tanımı; D-1…D-10
  kararları; `docs/kuantum-rehberi.md`; repo iskeleti + CI; modeller,
  `classify.py` + `algorithms.yaml` (53 algoritma); `engine.py`, `mosca.py`,
  `scanners/base.py`. Branch: `claude/nice-carson-avv8te`.
- **2026-11-04 (2)** — 1.4 `files` tarayıcısı: PEM (çok bloklu), DER, CSR,
  açık/özel anahtarlar, OpenSSH açık/özel anahtarlar (şifre çözmeden),
  ML-DSA/ML-KEM anahtarları; test anahtarları `tests/conftest.py`'de test
  sırasında üretiliyor; özel anahtar sızıntı testi (T-135). Branch:
  `claude/nice-gates-b8wil6`.
- **2026-11-05** — 1.5 konsol + JSON raporlayıcı (JSON şeması, snapshot
  testleri), 1.6 CLI (`scan files`, `report`, `--fail-on`, çıkış kodları,
  Mosca bayrakları); Mosca JSON geri okuma hatası düzeltildi; sslyze
  incelendi → D-11 açık kararı. Branch: `claude/nice-gates-b8wil6`.
- **2026-11-05 (2)** — D-11 = B (sslyze yok). Sertifika ayrıştırma
  `scanners/certs.py`'ye taşındı; `tls_names.py` (IANA tabloları),
  `tls_probe.py` (saf Python ClientHello probu, boş key_share ile HRR
  tekniği), `tls.py` + `scan tls`; sahte ve gerçek yerel sunucularla testler.
  Branch: `claude/nice-gates-b8wil6`.
- **2026-11-06** — Kalan tüm fazlar: D-12 (Semgrep yok) ile `code`
  tarayıcısı (Python AST, Java/Kotlin, JS/TS, Go); `ssh` tarayıcısı;
  `scan all`; HTML ve CycloneDX 1.6 CBOM; öneriler; `diff`; Mosca eşleme
  dosyası; GitHub Action; Docker; yayın iş akışı; öğren not defterleri;
  README, CHANGELOG, örnek raporlar, geçiş rehberi, Türkçe kullanım
  kılavuzu ve teknik özet. Sürüm 0.3.0. Branch: `claude/nice-gates-b8wil6`.

---

## Analiz özeti (2026-11-04)

**Analiz anındaki durum:** Repoda yalnızca `CLAUDE.md` vardı. Kod, paket yapısı, test, CI
ve lisans dosyaları henüz yok. Varsayılan branch `master`.

**CLAUDE.md'de tespit edilen tutarsızlık ve boşluklar:**

1. **Branch adı:** CLAUDE.md `main` diyor, repodaki varsayılan branch `master`.
2. **Tarayıcı çıktısı vs. sınıflandırma:** §6 "tarayıcı yalnızca `list[Finding]`
   döndürür" ve "risk sınıfını `classify` atar" diyor. `Finding` risk içeriyorsa
   tarayıcı onu dolduramaz → ara bir `Observation` modeli gerekiyor (D-1).
3. **Bilinmeyen algoritmalar:** Risk sınıflarında kural setinde olmayan
   algoritmalar için bir karşılık yok → `UNKNOWN` sınıfı önerildi (D-3).
4. **Çakışan sınıflar:** "RSA → VULNERABLE" ve "RSA < 2048 → BROKEN" aynı anda
   eşleşir. Öncelik kuralı tanımlı değil → "en kötü olan kazanır" önerildi.
5. **Bağlama bağlı sınıflandırma:** SHA-1 imzada BROKEN, HMAC içinde değil.
   Sınıflandırmanın algoritma adı + kullanım amacı (primitive) ile yapılması gerek.
6. **Belirsiz sınıflar:** "SHA-256 tabanlı kısa çıktılar" (WEAKENED) tanımsız;
   3DES klasik olarak da zayıf (Sweet32, NIST 2023'te kullanımdan kaldırdı) →
   BROKEN olabilir; AES-128 NIST'e göre hâlâ kabul edilebilir. → D-9.
7. **TLS'te PQ grupları:** `sslyze`'ın kullandığı `nassl` eski bir OpenSSL ile
   geliyor; X25519MLKEM768 gibi hibrit grupları büyük olasılıkla algılayamaz.
   Ayrı bir ClientHello probu gerekiyor (D-2). *Doğrulanmalı.*
8. **SSH'ta paramiko:** paramiko desteklemediği algoritmaları sunan sunucularda
   (ör. yalnızca `mlkem768x25519-sha256`) müzakere aşamasında hata verir.
   KEXINIT'i ham soketle okumak daha basit ve tamamen pasif (D-5).
9. **CLI seçenekleri tutarsız:** §9'da `--output`, `--format/--out` ve `--cbom`
   birlikte geçiyor → tek tip `--format` + `--out` önerildi (D-8).
10. **Mosca z değeri:** CRQC'ye kalan süre (z) için varsayılan yok; aracın bir
    kuantum takvimi iddia etmemesi için kullanıcıdan alınmalı (D-7).
11. **Test fixture'ları:** Özel anahtarları repoya commit'lemek GitHub secret
    scanning / push protection'ı tetikler → test sırasında üretilmeli.
12. **Özel anahtar içeriği kuralı** yalnızca `code` tarayıcısı için yazılmış;
    asıl anahtar dosyalarını bulan `files` tarayıcısı. Kural tüm tarayıcılara
    ve hata mesajlarına uygulanmalı.
13. **CI için çıkış kodu** (`--fail-on`) tanımlı değil; v0.3'teki GitHub Action
    buna dayanacağı için baştan tasarlanmalı.
14. **CBOM:** `cyclonedx-python-lib`'in CycloneDX 1.6 `cryptoProperties`
    desteği sürüm sürüm değişiyor. *Doğrulanmalı.*
15. **Semgrep** ağır bir bağımlılık ve Windows desteği sınırlı → opsiyonel
    extra olarak sunulması önerildi (D-6).

---

## Kararlar

D-1 … D-10 2026-11-04'te, D-11 2026-11-05'te onaylandı ve `CLAUDE.md` ile
`docs/architecture.md`'ye işlendi.

| #    | Konu | Karar |
| ---- | ---- | ----- |
| D-1  | Tarayıcı çıktı tipi | Tarayıcılar `Observation` döndürür, `engine.py` `classify` ile `Finding`'e çevirir |
| D-2  | TLS PQ grup tespiti | Kendi minimal TLS 1.3 ClientHello sorgumuz (D-11 ile tüm TLS taraması buna genişledi) |
| D-3  | Bilinmeyen algoritma | `UNKNOWN` risk sınıfı; çakışmada en kötü sınıf kazanır; sınıf bağlama (primitive) göre belirlenir |
| D-4  | Eşzamanlılık modeli | `ThreadPoolExecutor` |
| D-5  | SSH uygulaması | paramiko yok; ham soket + KEXINIT ayrıştırıcı |
| D-6  | Ağır bağımlılıklar | `[code]`, `[report]` opsiyonel extra; Python için AST yedeği (`[tls]` D-11 ile kalktı) |
| D-7  | Mosca z | Varsayılan yok; x, y, z üçü de verilmezse skor hesaplanmaz |
| D-8  | CLI çıktı seçenekleri | `--format {console,json,html,cbom}` + `--out PATH`; çıkış kodları 0/1/2/3 |
| D-9  | Belirsiz sınıflar | 3DES → BROKEN, AES-128 → WEAKENED, SHA-256 → PQ_SAFE (YAML'da `# TODO: doğrula`) |
| D-10 | Varsayılan branch | `master` kalır |
| D-12 | Kod tarama motoru | Semgrep kullanılmaz (72 MB, yalnızca Linux/macOS tekerleği). Python için `ast`, Java/Kotlin, JS/TS, Go için yorumları silinmiş kaynakta düzenli ifade kuralları; kurallar `rules/code_rules.yaml` (2026-11-06). `[code]` extra'sı kaldırıldı |
| D-11 | TLS için sslyze | sslyze kullanılmaz; sürüm, cipher suite, grup ve sertifika kendi saf Python probumuzla (+ TLS 1.3 sertifikası için `ssl`). `[tls]` extra'sı kaldırıldı (2026-11-05, seçenek B) |

---

## Faz 0 — Sistem tanımı

- [x] **T-001** Sistem tanımı taslağı (`docs/architecture.md`)
- [x] **T-002** Açık kararları (D-1 … D-10) netleştir, CLAUDE.md'yi güncelle
- [x] **T-004** Öğretici kavram belgesi (`docs/kuantum-rehberi.md`) — yeni kavramlarla büyümeye devam eder
- [x] **T-003** `algorithms.yaml` için kapsam listesi: hangi algoritma, alias,
  primitive ve sınıf (TLS cipher suite'leri, TLS grupları, SSH KEX/host key,
  X.509 imza OID'leri, kod API'leri) — tablo olarak çıkar

## Faz 1 — v0.1 MVP

### 1.1 Repo iskeleti (`chore/scaffold`)

- [x] **T-101** `pyproject.toml` (hatchling, `src/` düzeni, `pqc-scan` entry
  point, Python ≥ 3.11, extras: `dev`, `tls`, `code`, `all`)
- [x] **T-102** `src/pqc_scan/__init__.py` (`__version__`), boş `cli.py`
  (`pqc-scan --version` çalışsın)
- [x] **T-103** `ruff`, `mypy --strict`, `pytest` + `pytest-cov` yapılandırması
- [x] **T-104** `.pre-commit-config.yaml`
- [x] **T-105** `.github/workflows/ci.yml` — Python 3.11/3.12/3.13 matrisi:
  ruff check, ruff format --check, mypy, pytest (kapsama ≥ %80)
- [x] **T-106** `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`,
  `.gitignore`, iskelet `README.md` (etik uyarı dahil)

**Kabul:** `pip install -e ".[dev]"` → `pqc-scan --version` çalışır; CI yeşil.

### 1.2 Çekirdek modeller ve sınıflandırma (`feat/core-models`)

- [x] **T-111** `models.py`: `RiskClass`, `Primitive`, `Algorithm`, `Asset`,
  `Observation`, `Finding`, `ScanError`, `ScanResult`, `ScanConfig`
- [x] **T-112** `algorithms.yaml` şeması (pydantic) + yükleyici
  (`importlib.resources`)
- [x] **T-113** `algorithms.yaml` ilk içerik (T-003 tablosundan); belirsizler
  `# TODO: doğrula`
- [x] **T-114** `classify.py`: ad normalizasyonu, alias indeksi, kural
  değerlendirme (en kötü kazanır), `UNKNOWN` yedeği
- [x] **T-115** `tests/test_models.py`, `tests/test_classify.py` (her risk
  sınıfı, anahtar boyutu sınırları, primitive bağlamı, bilinmeyen ad,
  bozuk YAML)

**Kabul:** CLAUDE.md §3'teki tüm örnekler beklenen sınıfı döndürür.

### 1.3 Tarama motoru (`feat/engine`)

- [x] **T-121** `scanners/base.py`: `Scanner` ABC, `ScanTargetError`
- [x] **T-122** `engine.py`: hedef dağıtımı, eşzamanlılık sınırı, zaman aşımı,
  hata → `ScanError`, sınıflandırma, asset tekilleştirme, sıralama,
  deterministik `Finding.id`
- [x] **T-123** Testler: sahte tarayıcıyla hata izolasyonu, eşzamanlılık sınırı,
  sıralama

### 1.4 `files` tarayıcısı (`feat/files-scanner`)

- [x] **T-131** Dizin gezintisi (exclude listesi, boyut sınırı, symlink takip
  etmeme)
- [x] **T-132** PEM (çoklu blok), DER sertifika, açık/özel anahtar ayrıştırma
- [x] **T-133** OpenSSH açık anahtarları (`*.pub`, `authorized_keys`,
  `known_hosts`) ve OpenSSH özel anahtar başlığı (yalnızca tip/boyut)
- [x] **T-134** `tests/conftest.py`: RSA-1024/2048/4096, EC P-256/P-384,
  Ed25519, DSA anahtar ve sertifikalarını test sırasında üret
- [x] **T-135** Test: özel anahtar içeriğinin hiçbir çıktıda (rapor, hata
  mesajı, log) geçmediğini doğrulayan test

### 1.5 Konsol ve JSON raporlayıcı (`feat/reporters-basic`)

- [x] **T-141** `reporters/console.py` (rich tablo, risk renkleri, özet, hatalar)
- [x] **T-142** `reporters/json_report.py` + JSON Schema dışa aktarımı
- [x] **T-143** Snapshot testleri

### 1.6 CLI (`feat/cli`)

- [x] **T-151** `scan files`, `scan code`, `scan tls`, `scan ssh`, `scan all`, `report`, `diff`
  komutları; `--targets` dosyası; ortak seçenekler (D-8)
- [x] **T-152** `--fail-on` ve çıkış kodları (0/1/2/3)
- [x] **T-153** `--help` içinde yetkilendirme uyarısı
- [x] **T-154** `typer.testing.CliRunner` ile uçtan uca testler

**Not:** 1.4 + 1.5 + 1.6 bittiğinde `pqc-scan scan files ./repo` uçtan uca
çalışır — ilk kullanılabilir sürüm.

### 1.7 `tls` tarayıcısı (`feat/tls-scanner`)

- [x] **T-161** Sürüm, cipher suite ve sertifika zinciri taraması — D-11 ile
  sslyze yerine kendi probumuz + TLS 1.3 sertifikası için `ssl`
- [x] **T-162** Cipher suite ayrıştırıcı (`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
  → kex/auth/cipher/mac bileşenleri)
- [x] **T-163** PQ grup probu: TLS 1.3 ClientHello (supported_groups +
  key_share), ServerHello/HRR okuma, el sıkışmayı tamamlamadan kapatma (D-2)
- [x] **T-164** Testler: yerel `ssl` sunucusu (127.0.0.1), kaydedilmiş
  ServerHello baytlarıyla prob testleri

### 1.8 `code` tarayıcısı (`feat/code-scanner`)

D-12 ile Semgrep yerine yerleşik motorlar kullanıldı.

- [x] **T-171** Python kuralları (`cryptography`, `pycryptodome`, `hashlib`,
  `hmac`, `ssl`, `paramiko`, `PyJWT`) — AST ile
- [x] **T-172** Java/Kotlin kuralları (JCA: `KeyPairGenerator`, `KeyGenerator`,
  `Signature`, `Cipher`, `MessageDigest`, `Mac`, `KeyAgreement`, `SSLContext`)
- [x] **T-173** Kural verisi (`rules/code_rules.yaml`) → `Observation`
  dönüşümü; dönüştürücüler (JCA, OpenSSL, JOSE, TLS sürümü, WebCrypto)
- [x] **T-174** `tests/fixtures/code/` örnekleri ve testleri

### 1.9 README ve yayın hazırlığı (`docs/readme`)

- [x] **T-181** README: kurulum, kullanım, örnek çıktı, risk sınıfları, etik uyarı
- [x] **T-182** Demo görseli (`docs/demo.svg`, GIF yerine rich ile üretilen
  SVG) ve `examples/` altında örnek raporlar
- [x] **T-183** CHANGELOG; sürüm 0.3.0 (etiket kullanıcı tarafından
  `master`'a birleştirdikten sonra atılacak)

## Faz 2 — v0.2

- [x] **T-201** `ssh` tarayıcısı: banner + KEXINIT ham ayrıştırıcı (D-5),
  sahte sunucu ile testler
- [x] **T-202** HTML raporu (`templates/report.html.j2`, tek dosya, harici
  kaynak yok)
- [x] **T-203** CycloneDX 1.6 CBOM çıktısı (`cyclonedx-python-lib` 11,
  resmi şemaya karşı doğrulanıyor)
- [x] **T-204** `mosca.py` + `--mosca-x/-y/-z` + `--mosca-file` (varlık bazlı)
- [x] **T-205** JavaScript/TypeScript kuralları (Node `crypto`, WebCrypto,
  `node-forge`, JWT)
- [x] **T-206** Go kuralları (`crypto/rsa`, `crypto/ecdsa`, `crypto/ecdh`,
  `crypto/mlkem`, `crypto/tls` yapılandırması)
- [~] **T-207** PyPI yayını: `release.yml` hazır (trusted publishing); ilk
  yayın için PyPI ve GitHub ortam kurulumu kullanıcıda (bkz.
  `docs/kullanim-kilavuzu.md` §11)

## Faz 3 — v0.3 ve sonrası

- [x] **T-301** GitHub Action (`action.yml`): PR'da yalnızca yeni bulgular
  (`pqc-scan diff`, satır numarası/yol bağımsız eşleme)
- [x] **T-302** Docker imajı (root olmayan kullanıcı; CI'da derleniyor)
- [x] **T-303** "Öğren" bölümü: `docs/learn/` BB84, Shor, Grover not
  defterleri (saf Python, testlerde çalıştırılıyor)
- [x] **T-304** Bulgu bazlı öneriler (konsol + HTML) ve
  `docs/migration-guide.md` (nginx, Apache, OpenSSH, Go örnekleri)
