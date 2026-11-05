# CLAUDE.md — PQC Readiness Scanner

> **Yeni oturum mu?** Önce [§12 Yeni oturumda devam etme](#12-yeni-oturumda-devam-etme) bölümünü oku; güncel durum ve sıradaki görev `TASKS.md` → "Şu anki durum" bölümündedir.

Bu dosya, Claude Code'un bu repoda her oturumda okuduğu proje bağlamıdır. Projenin amacı, kapsamı, mimarisi ve çalışma kuralları burada tanımlıdır. Kararlar değiştikçe bu dosyayı güncel tut.

---

## 1. Proje özeti

**PQC Readiness Scanner** (çalışma adı: `pqc-scan`), bir kurumun sistemlerindeki ve kod tabanındaki **kuantum bilgisayarlara karşı savunmasız kriptografiyi** bulan, raporlayan ve post-kuantum kriptografiye (PQC) geçiş için önceliklendiren açık kaynak bir komut satırı aracıdır.

Çıktısı bir **kriptografik envanterdir (CBOM)**: hangi sistem, hangi algoritmayı, hangi anahtar boyutuyla kullanıyor ve bu kuantum çağında ne kadar risk taşıyor.

Referans standartlar:
- NIST FIPS 203 — ML-KEM (anahtar kapsülleme)
- NIST FIPS 204 — ML-DSA (dijital imza)
- NIST FIPS 205 — SLH-DSA (hash tabanlı imza)
- CycloneDX CBOM (kriptografik malzeme listesi formatı)

## 2. MVP kapsamı

İlk sürüm (v0.1) dört tarayıcı modülü ve ortak bir raporlama katmanından oluşur:

| Modül | Girdi | Ne bulur |
| --- | --- | --- |
| `tls` | `host:port` listesi | Sertifika anahtar tipi/boyutu, imza algoritması, TLS sürümleri, şifre takımları, anahtar değişim grupları (hibrit PQ grupları dahil, ör. X25519MLKEM768) |
| `ssh` | `host:port` listesi | Host key algoritmaları, KEX algoritmaları (ör. `sntrup761x25519`, `mlkem768x25519` desteği var mı) |
| `code` | Yerel klasör / repo | Kaynak koddaki kripto API kullanımı (Python, Java, JavaScript/TypeScript, Go) — RSA/ECDSA/ECDH/DH çağrıları, zayıf hash'ler, sabit kodlanmış anahtar boyutları |
| `files` | Yerel klasör | Repo içindeki PEM/DER sertifika ve anahtar dosyaları, `.pub` SSH anahtarları |

Kapsam dışı (şimdilik): aktif saldırı, zafiyet istismarı, kimlik doğrulama gerektiren tarama, ikili (binary) analiz.

## 3. Risk sınıflandırması

Her bulgu şu sınıflardan birine düşer:

| Sınıf | Anlamı | Örnekler |
| --- | --- | --- |
| `VULNERABLE` | Shor algoritmasıyla kırılabilir | RSA (tüm boyutlar), ECDSA, ECDH, Ed25519, X25519 (tek başına), DH, DSA |
| `WEAKENED` | Grover ile güvenlik payı yarıya iner | AES-128, SHA-224 |
| `HYBRID` | Klasik + PQ birlikte | X25519MLKEM768, hibrit imzalar |
| `PQ_SAFE` | Kuantuma dayanıklı kabul edilen | ML-KEM, ML-DSA, SLH-DSA, AES-256, SHA-256, SHA-384/512, SHA3 |
| `BROKEN` | Kuantumdan bağımsız olarak zaten zayıf | MD5, SHA-1 imza, RC4, 3DES, DES, TLS 1.0/1.1, SSLv2/3, RSA < 2048 |
| `UNKNOWN` | Kural setinde yok, manuel inceleme gerekir | Tanınmayan algoritma adları |

Sınıflandırma kuralları tek bir yerde, veri olarak tutulur (`src/pqc_scan/rules/algorithms.yaml`); kod içine dağıtılmaz.

Sınıflandırma ilkeleri (karar: D-3, D-9):
- **Önem sırası:** `BROKEN` > `VULNERABLE` > `WEAKENED` > `UNKNOWN` > `HYBRID` > `PQ_SAFE`. Kurallar varsayılan sınıfı geçersiz kılar; bir algoritmaya birden çok kural uyarsa **en kötü olan** kazanır (ör. RSA-1024 → `BROKEN`). Tanınmayan ad → `UNKNOWN`.
- **Bağlam önemlidir:** Sınıf, algoritma adı + kullanım amacı (primitive: imza, hash, MAC, …) ile belirlenir. Ör. SHA-1 imzada `BROKEN`, HMAC içinde daha hafif sınıflandırılır.
- 3DES → `BROKEN`, AES-128 → `WEAKENED`, SHA-256 → `PQ_SAFE` kararları alındı; YAML'da `# TODO: doğrula` notu korunur.

Opsiyonel öncelik skoru: **Mosca teoremi** (x + y > z → risk). x = verinin gizli kalma süresi, y = geçiş süresi, z = kuantum bilgisayarın hazır olmasına kalan süre. **Üçü de kullanıcıdan alınır; z için varsayılan yoktur** (araç bir kuantum takvimi iddia etmez). Üçü verilmezse skor hesaplanmaz. (karar: D-7)

## 4. Teknoloji yığını

- Python 3.11+
- CLI: `typer` · terminal çıktısı: `rich` · veri modelleri: `pydantic` v2
- TLS: ek bağımlılık yok — kendi saf Python ClientHello sorgumuz (sürümler, şifre takımları, hibrit PQ grupları dahil anahtar değişim grupları) + sertifika için standart `ssl` modülü; sertifika/anahtar ayrıştırma: `cryptography` (karar: D-2, D-11 — sslyze kullanılmaz)
- SSH: ek bağımlılık yok — ham soketle sunucunun KEXINIT mesajı okunur, oturum açılmaz (karar: D-5, paramiko kullanılmaz)
- Kod tarama: Semgrep kuralları (`rules/semgrep/`) + basit dosyalar için Python AST
- Rapor: JSON, HTML (`jinja2`), CycloneDX CBOM (`cyclonedx-python-lib`)
- Geliştirme: `pytest`, `ruff` (lint + format), `mypy` (strict), `pre-commit`
- Paketleme: `pyproject.toml` (hatchling), `src/` düzeni
- Ağır bağımlılıklar opsiyonel extra'dır: `[code]` (semgrep), `[report]` (jinja2, cyclonedx), `[dev]`, `[all]`. Semgrep yoksa Python dosyaları için AST yedeği çalışır. (karar: D-6)
- Eşzamanlılık: `concurrent.futures.ThreadPoolExecutor` (karar: D-4)

Yeni bir bağımlılık eklemeden önce gerekçesini PR açıklamasında belirt.

## 5. Klasör yapısı (hedef)

```
pqc-scan/
├── CLAUDE.md
├── TASKS.md                 # görev listesi ve açık kararlar
├── README.md
├── LICENSE                  # Apache-2.0
├── SECURITY.md
├── CONTRIBUTING.md
├── pyproject.toml
├── .github/workflows/ci.yml
├── docs/
│   ├── architecture.md      # sistem tanımı (İngilizce)
│   └── kuantum-rehberi.md   # öğretici terimler belgesi (Türkçe)
├── src/pqc_scan/
│   ├── __init__.py
│   ├── cli.py               # typer uygulaması: scan tls|ssh|code|files|all, report
│   ├── models.py            # Observation, Finding, Asset, Algorithm, RiskClass, ScanResult
│   ├── engine.py            # tarayıcıları çalıştırır, hataları toplar, classify çağırır
│   ├── classify.py          # algoritma → risk sınıfı eşlemesi
│   ├── mosca.py             # öncelik skoru
│   ├── scanners/
│   │   ├── base.py          # Scanner arayüzü (abstract)
│   │   ├── tls.py
│   │   ├── ssh.py
│   │   ├── code.py
│   │   └── files.py
│   ├── reporters/
│   │   ├── console.py
│   │   ├── json_report.py
│   │   ├── html_report.py
│   │   └── cbom.py
│   ├── rules/
│   │   ├── algorithms.yaml
│   │   └── semgrep/*.yaml
│   └── templates/report.html.j2
├── tests/
│   ├── fixtures/            # test için üretilmiş sertifikalar, anahtarlar, örnek kodlar
│   ├── test_classify.py
│   ├── test_scanner_tls.py
│   └── ...
└── examples/                # örnek rapor çıktıları
```

## 6. Mimari kurallar

- Her tarayıcı `scanners/base.py` içindeki `Scanner` arayüzünü uygular ve yalnızca `list[Observation]` döndürür (risk sınıfı içermeyen ham gözlem). Tarayıcılar risk sınıflarını ve rapor formatını bilmez. (karar: D-1)
- Sınıflandırma (`classify.py`) tarayıcılardan bağımsızdır; `engine.py` her `Observation`'ı `classify`'a verir ve sonucu `Finding` olarak `ScanResult`'a ekler.
- Raporlayıcılar yalnızca `ScanResult` modelini tüketir.
- Ağ taramaları için zaman aşımı ve eşzamanlılık sınırı her zaman yapılandırılabilir olsun; varsayılanlar ihtiyatlı olsun (ör. 5 sn zaman aşımı, en fazla 10 eşzamanlı bağlantı).
- Hata olan bir hedef taramanın tamamını durdurmaz; hata `ScanResult.errors` içine yazılır.
- CLI çıktısı her komutta aynı iki seçenekle belirlenir: `--format {console,json,html,cbom}` ve `--out PATH`. Çıkış kodları: `0` başarılı · `1` `--fail-on` eşiği aşıldı · `2` kullanım hatası · `3` tüm hedefler hata verdi. (karar: D-8)

## 7. Güvenlik ve etik kurallar

- Araç **pasif keşif** yapar: el sıkışma bilgisini okur, oturum açmaz, istismar denemez, parola denemez.
- README ve `--help` çıktısında açık uyarı bulunur: yalnızca sahibi olunan veya yazılı izin alınmış sistemler taranmalıdır.
- **Hiçbir tarayıcı** bulduğu özel anahtarların **içeriğini** rapora, hata mesajına veya loga yazmaz; yalnızca dosya yolu, tip ve boyut raporlanır. Kod bulgularında satırın kendisi değil, yalnızca dosya yolu, satır numarası ve API adı yer alır.
- Testler gerçek internet hedeflerine bağlanmaz; testler için yerel test sunucuları kullanılır.
- Test anahtarları ve sertifikaları **test sırasında** `tests/conftest.py` içinde üretilir; özel anahtar repoya commit'lenmez (GitHub secret scanning'i tetikler). `tests/fixtures/` yalnızca açık anahtar, örnek kod ve bozuk örnekler içindir.

## 8. Kod ve repo kuralları

- Kod, yorumlar, commit mesajları, README ve dokümantasyon **İngilizce** (uluslararası görünürlük için). Bu CLAUDE.md ve proje içi notlar Türkçe kalabilir.
- Tip ipuçları zorunlu; `mypy --strict` temiz geçmeli.
- Her yeni modül için birim testi; hedef kapsama ≥ %80.
- Commit mesajları Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`.
- Her özellik ayrı branch ve PR ile gelir (`feat/tls-scanner` gibi); `master` her zaman çalışır durumda. (karar: D-10)
- Küçük, gözden geçirilebilir PR'lar tercih edilir.

## 9. Sık kullanılan komutlar

```bash
# Kurulum (geliştirme)
pip install -e ".[dev]"
pre-commit install

# Kalite kontrolleri
ruff check . && ruff format --check .
mypy src
pytest -q --cov=pqc_scan

# Kullanım örnekleri
pqc-scan scan tls example.com:443 --format json --out report.json
pqc-scan scan code ./my-repo --format html --out report.html
pqc-scan scan all --targets targets.txt --path ./my-repo --format cbom --out cbom.json
pqc-scan scan files ./my-repo --fail-on VULNERABLE   # CI için: eşik aşılırsa çıkış kodu 1
```

## 10. Yol haritası

**v0.1 — MVP**
- [x] Repo iskeleti, `pyproject.toml`, CI (ruff + mypy + pytest)
- [x] `models.py` ve `classify.py` + `algorithms.yaml` (testleriyle)
- [x] Tarama motoru (`engine.py`) ve `Scanner` arayüzü
- [x] `files` tarayıcısı (en kolay; çekirdeği test etmek için ilk bu)
- [ ] `tls` tarayıcısı
- [ ] `code` tarayıcısı (Semgrep kuralları: Python ve Java ile başla)
- [x] Konsol ve JSON raporlayıcı
- [ ] README: kurulum, kullanım, demo GIF, etik uyarı

**v0.2**
- [ ] `ssh` tarayıcısı
- [ ] HTML rapor ve CycloneDX CBOM çıktısı
- [ ] Mosca öncelik skoru
- [ ] JavaScript/TypeScript ve Go kod kuralları
- [ ] PyPI yayını

**v0.3 ve sonrası**
- [ ] GitHub Action olarak kullanım (PR'larda kripto değişikliği uyarısı)
- [ ] Docker imajı
- [ ] "Öğren" bölümü: BB84 ve Shor/Grover açıklamalı not defterleri
- [ ] Bulunan zayıflıklar için geçiş önerileri (hibrit TLS yapılandırma örnekleri)

## 11. Claude Code için çalışma şekli

- Bir göreve başlamadan önce ilgili bölümü (kapsam, mimari kurallar) kontrol et; kurala uymayan bir yaklaşım gerekiyorsa önce sor.
- Büyük bir değişiklik öncesi kısa bir plan çıkar, sonra uygula.
- Her görevin sonunda: testleri ve lint'i çalıştır, yol haritasındaki ilgili maddeyi işaretle, kısa bir özet yaz.
- Belirsiz bir algoritma sınıflandırması gördüğünde tahmin etme; `algorithms.yaml` içine `# TODO: doğrula` notuyla ekle ve özette belirt.
- Yeni bir kuantum/kriptografi kavramı projeye girdiğinde `docs/kuantum-rehberi.md` belgesine sade, öğretici bir açıklama ekle.
- Görev durumlarını `TASKS.md` içinde güncel tut.

## 12. Yeni oturumda devam etme

Kullanıcı "projeye devam et" (veya benzeri) dediğinde ek soru sormadan şu adımları izle:

1. **Durumu oku:** `TASKS.md` → "Şu anki durum" bölümü sıradaki görevi ve onun ayrıntılı planını içerir. Gerekirse `docs/architecture.md`'ye bak.
2. **Ortamı kur:**
   ```bash
   python3.11 -m venv .venv          # yoksa python3 (≥ 3.11)
   .venv/bin/pip install -e ".[dev]"
   .venv/bin/ruff check . && .venv/bin/mypy src && .venv/bin/pytest -q --cov=pqc_scan
   ```
   Başlamadan önce tüm kontrollerin yeşil olduğunu doğrula.
3. **Git kimliğini ayarla** (her yeni klonda gerekir, commit'ler kullanıcının adıyla görünmeli):
   ```bash
   git config user.name "Yusuf Taha"
   git config user.email "ytkurt06@gmail.com"
   ```
   Commit mesajlarına `Co-Authored-By`, `Claude-Session` veya benzeri Claude/asistan imza satırları **ekleme** (kullanıcının açık talebi). Commit mesajları İngilizce ve Conventional Commits biçiminde.
4. **Branch:** Oturum bir branch belirttiyse onu kullan; belirtmediyse güncel `master`'dan `feat/<görev>` aç. `.venv/` asla commit'lenmez (`.gitignore`'da).
5. **Uygula:** Sıradaki görevi kısa bir planla başlat, kod + testleri yaz. Mantıklı bir bütün (ör. bir tarayıcı) bittiğinde dur ve push'la; birden fazla bağımsız özelliği tek commit'e koyma.
6. **Bitirirken (her görevde):**
   - ruff, ruff format, mypy, pytest (kapsama ≥ %80) geçmeli.
   - `TASKS.md`: görev kutularını işaretle, "Şu anki durum" bölümünü ve "Oturum günlüğü"nü güncelle, sıradaki görevin planını yaz.
   - `CLAUDE.md` §10 yol haritasında tamamlanan maddeyi işaretle.
   - Yeni bir kavram girdiyse `docs/kuantum-rehberi.md`'ye ekle.
   - Belirsiz sınıflandırmaları (`# TODO: doğrula`) özette listele.
7. **Kullanıcıyla iletişim:** Kullanıcı kriptografi/kuantum konusunda uzman değil. Türkçe, sade yaz; teknik terim kullanırsan bir cümleyle açıkla ve gerekirse rehberdeki bölüme yönlendir. Karar gerektiren konularda seçenekleri ve önerini açık, jargon olmadan sun.

