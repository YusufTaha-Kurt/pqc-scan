# pqc-scan

[Türkçe](README.tr.md) · [English](README.md)

Kaynak kodda, anahtar ve sertifika dosyalarında, TLS ve SSH uç noktalarında kullanılan kriptografiyi envantere alır. Bulguları kuantum riskine göre sınıflandırır ve geçiş önerileri sunar.

## Kurulum ve ilk tarama

Python 3.11 veya üzeriyle depo kökünde çalıştırın.

```sh
python -m pip install ".[report]"
pqc-scan --lang tr scan code . --exclude tests/fixtures
pqc-scan --lang tr scan all --path . --format html --out rapor.html
```

Her çalıştırmada Türkçe kullanmak için PowerShell'de `$env:PQC_SCAN_LANG = "tr"`, Bash'te `export PQC_SCAN_LANG=tr` kullanın. JSON alanları, algoritma adları ve risk kodları otomasyonlar için sabittir. Konsol ve HTML raporlarında dosya kapsamını tarayıcı başına görebilirsiniz. JSON raporu ayrıca atlanan yolları içerir.

## GitHub Actions

Bu depoyu checkout eden bir iş akışında yerel Action'ı şöyle kullanabilirsiniz. Başka bir depodan kullanırken `uses` için yayımlanmış değişikliği içeren commit'i seçin.

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: ./
    with:
      language: tr
      path: .
      exclude: tests/fixtures
      fail-on: BROKEN
```

Yalnızca ağ uç noktalarını taramak için `path: ""` ile birlikte `tls` veya `ssh` girdisini verin. Yalnızca yetkiniz olan sistemleri tarayın. Bütün hedefler başarısızsa Action raporları oluşturur ve 3 koduyla çıkar.

[Kullanım kılavuzu](docs/kullanim-kilavuzu.md) · [Teknik özet](docs/teknik-ozet.md) · [Kuantum rehberi](docs/kuantum-rehberi.md)
