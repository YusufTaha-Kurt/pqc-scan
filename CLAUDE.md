# CLAUDE.md — PQC Readiness Scanner

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
| `WEAKENED` | Grover ile güvenlik payı yarıya iner | AES-128, SHA-256 tabanlı kısa çıktılar, 3DES |
| `HYBRID` | Klasik + PQ birlikte | X25519MLKEM768, hibrit imzalar |
| `PQ_SAFE` | Kuantuma dayanıklı kabul edilen | ML-KEM, ML-DSA, SLH-DSA, AES-256, SHA-384/512, SHA3 |
| `BROKEN` | Kuantumdan bağımsız olarak zaten zayıf | MD5, SHA-1 imza, RC4, TLS 1.0/1.1, RSA < 2048 |

Sınıflandırma kuralları tek bir yerde, veri olarak tutulur (`src/pqc_scan/rules/algorithms.yaml`); kod içine dağıtılmaz.

Opsiyonel öncelik skoru: **Mosca teoremi** (x + y > z → risk). Kullanıcı verinin gizli kalma süresi (x) ve geçiş süresini (y) verirse, rapor her varlık için aciliyet hesaplar.

## 4. Teknoloji yığını

- Python 3.11+
- CLI: `typer` · terminal çıktısı: `rich` · veri modelleri: `pydantic` v2
- TLS: `sslyze` · sertifika/anahtar ayrıştırma: `cryptography`
- SSH: `paramiko` (yalnızca KEXINIT/host key bilgisini okumak için, oturum açmadan)
- Kod tarama: Semgrep kuralları (`rules/semgrep/`) + basit dosyalar için Python AST
- Rapor: JSON, HTML (`jinja2`), CycloneDX CBOM (`cyclonedx-python-lib`)
- Geliştirme: `pytest`, `ruff` (lint + format), `mypy` (strict), `pre-commit`
- Paketleme: `pyproject.toml` (hatchling), `src/` düzeni

Yeni bir bağımlılık eklemeden önce gerekçesini PR açıklamasında belirt.

## 5. Klasör yapısı (hedef)

```
pqc-scan/
├── CLAUDE.md
├── README.md
├── LICENSE                  # Apache-2.0
├── SECURITY.md
├── CONTRIBUTING.md
├── pyproject.toml
├── .github/workflows/ci.yml
├── src/pqc_scan/
│   ├── __init__.py
│   ├── cli.py               # typer uygulaması: scan tls|ssh|code|files|all, report
│   ├── models.py            # Finding, Asset, Algorithm, RiskClass, ScanResult
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

- Her tarayıcı `scanners/base.py` içindeki `Scanner` arayüzünü uygular ve yalnızca `list[Finding]` döndürür. Tarayıcılar rapor formatını bilmez.
- Sınıflandırma (`classify.py`) tarayıcılardan bağımsızdır; tarayıcı ham algoritma adını verir, risk sınıfını `classify` atar.
- Raporlayıcılar yalnızca `ScanResult` modelini tüketir.
- Ağ taramaları için zaman aşımı ve eşzamanlılık sınırı her zaman yapılandırılabilir olsun; varsayılanlar ihtiyatlı olsun (ör. 5 sn zaman aşımı, en fazla 10 eşzamanlı bağlantı).
- Hata olan bir hedef taramanın tamamını durdurmaz; hata `ScanResult.errors` içine yazılır.

## 7. Güvenlik ve etik kurallar

- Araç **pasif keşif** yapar: el sıkışma bilgisini okur, oturum açmaz, istismar denemez, parola denemez.
- README ve `--help` çıktısında açık uyarı bulunur: yalnızca sahibi olunan veya yazılı izin alınmış sistemler taranmalıdır.
- Kod tarayıcısı bulduğu özel anahtarların **içeriğini** asla rapora yazmaz; yalnızca dosya yolu, tip ve boyut raporlanır.
- Testler gerçek internet hedeflerine bağlanmaz; testler için yerel test sunucuları ve `tests/fixtures/` içindeki üretilmiş anahtarlar kullanılır.

## 8. Kod ve repo kuralları

- Kod, yorumlar, commit mesajları, README ve dokümantasyon **İngilizce** (uluslararası görünürlük için). Bu CLAUDE.md ve proje içi notlar Türkçe kalabilir.
- Tip ipuçları zorunlu; `mypy --strict` temiz geçmeli.
- Her yeni modül için birim testi; hedef kapsama ≥ %80.
- Commit mesajları Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`.
- Her özellik ayrı branch ve PR ile gelir (`feat/tls-scanner` gibi); `main` her zaman çalışır durumda.
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
pqc-scan scan tls example.com:443 --output report.json
pqc-scan scan code ./my-repo --format html --out report.html
pqc-scan scan all --targets targets.txt --path ./my-repo --cbom cbom.json
```

## 10. Yol haritası

**v0.1 — MVP**
- [ ] Repo iskeleti, `pyproject.toml`, CI (ruff + mypy + pytest)
- [ ] `models.py` ve `classify.py` + `algorithms.yaml` (testleriyle)
- [ ] `files` tarayıcısı (en kolay; çekirdeği test etmek için ilk bu)
- [ ] `tls` tarayıcısı
- [ ] `code` tarayıcısı (Semgrep kuralları: Python ve Java ile başla)
- [ ] Konsol ve JSON raporlayıcı
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
