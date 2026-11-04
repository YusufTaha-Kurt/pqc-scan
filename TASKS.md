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

**Son güncelleme:** 2026-11-04

**Biten:** Faz 0 (sistem tanımı, kararlar), 1.1 repo iskeleti, 1.2 modeller +
sınıflandırma, 1.3 tarama motoru. 86 test, kapsama %99. Henüz kullanıcıya
dönük bir tarama komutu yok (`pqc-scan --version` çalışıyor).

**Sıradaki görev: 1.4 `files` tarayıcısı (T-131 … T-135).**
Bundan sonra 1.5 raporlayıcılar ve 1.6 CLI gelir; üçü bitince
`pqc-scan scan files ./repo` uçtan uca çalışır (ilk kullanılabilir sürüm).

### `files` tarayıcısı için plan

- **Dosya:** `src/pqc_scan/scanners/files.py` → `class FilesScanner(Scanner)`,
  `name = "files"`. Hedef bir klasör (veya tek dosya) yoludur; yol yoksa
  `ScanTargetError(ErrorKind.INVALID_TARGET, ...)`.
- **Gezinti:** `os.walk(followlinks=config.follow_symlinks)`; `config.exclude`
  içindeki klasörleri buda; `config.max_file_size`'dan büyük dosyaları atla.
  Tek bir dosyanın okunamaması veya ayrıştırılamaması hedefin tamamını
  düşürmez — sessizce atlanır (kripto dosyası olmayan dosyalar zaten çoğunluk).
- **Algılama (içeriğe göre, uzantıya güvenme):**
  - `-----BEGIN ` içeren dosyalar → her PEM bloğunu ayrı işle
    (CERTIFICATE, PUBLIC KEY, RSA/EC/DSA PRIVATE KEY, PRIVATE KEY,
    ENCRYPTED PRIVATE KEY, OPENSSH PRIVATE KEY, CERTIFICATE REQUEST).
  - `.der`, `.cer`, `.crt` → DER sertifika olarak dene.
  - `*.pub`, `authorized_keys`, `known_hosts` → OpenSSH açık anahtar satırları
    (`cryptography.hazmat.primitives.serialization.load_ssh_public_key`).
  - `OPENSSH PRIVATE KEY` → **şifre çözmeden** `openssh-key-v1` başlığındaki
    şifresiz açık anahtar bloğundan tip ve boyutu oku.
  - Şifreli PKCS#8 özel anahtar → tip bilinemez; `raw_name="encrypted private key"`
    (sınıflandırıcı `UNKNOWN` verir) — kabul edilebilir.
- **Gözlemler (`usage` değerleri):**
  - Sertifika: `file.certificate.public_key` (RSA/EC/Ed25519/… + `key_size`,
    `curve`), `file.certificate.signature` (imzalayan anahtarın algoritması,
    `signature_algorithm_oid`'den), `file.certificate.signature_hash`
    (`signature_hash_algorithm.name`, ör. `sha256`; Ed25519'da yok).
  - `file.private_key`, `file.public_key`, `file.ssh_public_key`.
  - `cryptography` nesne → ad eşlemesi: RSA → `RSA`, EC → `EC` (+ `curve.name`,
    `key_size`), Ed25519 → `Ed25519`, Ed448, DSA, X25519, X448.
    `cryptography` sürümünün ML-DSA/ML-KEM anahtarlarını destekleyip
    desteklemediğini kontrol et; destekliyorsa onları da eşle.
- **Asset:** `id = file://<mutlak yol>`; bir dosyada birden çok PEM bloğu
  varsa `#block-<n>` eki. `kind`: `certificate` / `private_key` / `public_key`.
  `location` = hedef köke göre göreli yol.
- **Güvenlik:** `Evidence.detail` yalnızca "PEM block 2" / "line 5" gibi
  konum bilgisi içerir; anahtar içeriği hiçbir yerde (rapor, hata, log) yer
  almaz.
- **Testler:** `tests/conftest.py` içinde session-scope fixture'larla
  `cryptography` kullanarak RSA-1024/2048, EC P-256/P-384, Ed25519, DSA
  anahtarları, kendinden imzalı sertifikalar, OpenSSH açık/özel anahtarları
  (şifreli ve şifresiz) ve çok bloklu bir PEM dosyası **test sırasında** üret
  (`tmp_path_factory`). `tests/test_scanner_files.py`: her tür doğru tip/boyutu
  verir; exclude ve boyut sınırı çalışır; symlink takip edilmez; bozuk PEM
  atlanır; **özel anahtarın base64 gövdesi `ScanResult` JSON'unda geçmez**
  (T-135).

### Bilinen notlar

- Geliştirme Python 3.11 venv ile yapıldı; testler 3.13'te de geçiyor.
- CI (`.github/workflows/ci.yml`) yalnızca `master`'a push ve PR'larda çalışır;
  GitHub'da henüz hiç çalıştırılmadı.
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

Tüm kararlar 2026-11-04'te onaylandı ve `CLAUDE.md` ile
`docs/architecture.md`'ye işlendi.

| #    | Konu | Karar |
| ---- | ---- | ----- |
| D-1  | Tarayıcı çıktı tipi | Tarayıcılar `Observation` döndürür, `engine.py` `classify` ile `Finding`'e çevirir |
| D-2  | TLS PQ grup tespiti | sslyze + kendi minimal TLS 1.3 ClientHello sorgumuz |
| D-3  | Bilinmeyen algoritma | `UNKNOWN` risk sınıfı; çakışmada en kötü sınıf kazanır; sınıf bağlama (primitive) göre belirlenir |
| D-4  | Eşzamanlılık modeli | `ThreadPoolExecutor` |
| D-5  | SSH uygulaması | paramiko yok; ham soket + KEXINIT ayrıştırıcı |
| D-6  | Ağır bağımlılıklar | `[tls]`, `[code]`, `[report]` opsiyonel extra; Python için AST yedeği |
| D-7  | Mosca z | Varsayılan yok; x, y, z üçü de verilmezse skor hesaplanmaz |
| D-8  | CLI çıktı seçenekleri | `--format {console,json,html,cbom}` + `--out PATH`; çıkış kodları 0/1/2/3 |
| D-9  | Belirsiz sınıflar | 3DES → BROKEN, AES-128 → WEAKENED, SHA-256 → PQ_SAFE (YAML'da `# TODO: doğrula`) |
| D-10 | Varsayılan branch | `master` kalır |

---

## Faz 0 — Sistem tanımı

- [x] **T-001** Sistem tanımı taslağı (`docs/architecture.md`)
- [x] **T-002** Açık kararları (D-1 … D-10) netleştir, CLAUDE.md'yi güncelle
- [~] **T-004** Öğretici kavram belgesi (`docs/kuantum-rehberi.md`) — süreç boyunca büyür
- [~] **T-003** `algorithms.yaml` için kapsam listesi: hangi algoritma, alias,
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

- [ ] **T-131** Dizin gezintisi (exclude listesi, boyut sınırı, symlink takip
  etmeme)
- [ ] **T-132** PEM (çoklu blok), DER sertifika, açık/özel anahtar ayrıştırma
- [ ] **T-133** OpenSSH açık anahtarları (`*.pub`, `authorized_keys`,
  `known_hosts`) ve OpenSSH özel anahtar başlığı (yalnızca tip/boyut)
- [ ] **T-134** `tests/conftest.py`: RSA-1024/2048/4096, EC P-256/P-384,
  Ed25519, DSA anahtar ve sertifikalarını test sırasında üret
- [ ] **T-135** Test: özel anahtar içeriğinin hiçbir çıktıda (rapor, hata
  mesajı, log) geçmediğini doğrulayan test

### 1.5 Konsol ve JSON raporlayıcı (`feat/reporters-basic`)

- [ ] **T-141** `reporters/console.py` (rich tablo, risk renkleri, özet, hatalar)
- [ ] **T-142** `reporters/json_report.py` + JSON Schema dışa aktarımı
- [ ] **T-143** Snapshot testleri

### 1.6 CLI (`feat/cli`)

- [ ] **T-151** `scan files`, `scan code`, `scan tls`, `scan all`, `report`
  komutları; `--targets` dosyası; ortak seçenekler (D-8)
- [ ] **T-152** `--fail-on` ve çıkış kodları (0/1/2/3)
- [ ] **T-153** `--help` içinde yetkilendirme uyarısı
- [ ] **T-154** `typer.testing.CliRunner` ile uçtan uca testler

**Not:** 1.4 + 1.5 + 1.6 bittiğinde `pqc-scan scan files ./repo` uçtan uca
çalışır — ilk kullanılabilir sürüm.

### 1.7 `tls` tarayıcısı (`feat/tls-scanner`)

- [ ] **T-161** sslyze entegrasyonu: protokol sürümleri, cipher suite'ler,
  sertifika zinciri
- [ ] **T-162** Cipher suite ayrıştırıcı (`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
  → kex/auth/cipher/mac bileşenleri)
- [ ] **T-163** PQ grup probu: TLS 1.3 ClientHello (supported_groups +
  key_share), ServerHello/HRR okuma, el sıkışmayı tamamlamadan kapatma (D-2)
- [ ] **T-164** Testler: yerel `ssl` sunucusu (127.0.0.1), kaydedilmiş
  ServerHello baytlarıyla prob testleri

### 1.8 `code` tarayıcısı (`feat/code-scanner`)

- [ ] **T-171** Semgrep kuralları — Python (`cryptography`, `pycryptodome`,
  `hashlib`, `ssl`, `paramiko`)
- [ ] **T-172** Semgrep kuralları — Java (JCA: `KeyPairGenerator`, `Signature`,
  `Cipher`, `MessageDigest`, `KeyAgreement`)
- [ ] **T-173** Kural metadata'sı → `Observation` dönüşümü; Semgrep yoksa
  Python AST yedeği (D-6)
- [ ] **T-174** `tests/fixtures/code/{python,java}` örnekleri ve testleri

### 1.9 README ve yayın hazırlığı (`docs/readme`)

- [ ] **T-181** README: kurulum, kullanım, örnek çıktı, risk sınıfları, etik uyarı
- [ ] **T-182** Demo GIF (ör. `vhs` ile) ve `examples/` altında örnek raporlar
- [ ] **T-183** `v0.1.0` etiketi, CHANGELOG

## Faz 2 — v0.2

- [ ] **T-201** `ssh` tarayıcısı: banner + KEXINIT ham ayrıştırıcı (D-5),
  sahte sunucu ile testler
- [ ] **T-202** HTML raporu (`templates/report.html.j2`, tek dosya, harici
  kaynak yok)
- [ ] **T-203** CycloneDX 1.6 CBOM çıktısı (önce kütüphane desteğini doğrula)
- [~] **T-204** `mosca.py` + `--mosca-x/-y/-z`; varlık bazlı eşleme dosyası
  (`mosca.py` ve motordaki hesaplama hazır; CLI bayrakları ve eşleme dosyası kaldı)
- [ ] **T-205** JavaScript/TypeScript Semgrep kuralları (Node `crypto`,
  WebCrypto, `node-forge`, `jsonwebtoken`)
- [ ] **T-206** Go Semgrep kuralları (`crypto/rsa`, `crypto/ecdsa`,
  `crypto/tls` yapılandırması)
- [ ] **T-207** PyPI yayını (trusted publishing ile GitHub Actions)

## Faz 3 — v0.3 ve sonrası

- [ ] **T-301** GitHub Action (PR'da yeni zayıf kripto kullanımı uyarısı;
  önceki `ScanResult` ile karşılaştırma için `Finding.id` kullanılır)
- [ ] **T-302** Docker imajı
- [ ] **T-303** "Öğren" bölümü: BB84, Shor, Grover not defterleri
- [ ] **T-304** Bulgu bazlı geçiş önerileri (hibrit TLS yapılandırma
  örnekleri: nginx, OpenSSL 3.5+, Go 1.24+)
