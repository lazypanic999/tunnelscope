# İlk deney: Veri gerçekten ulaşıyor mu?

Bu adımda iki program çalıştırıyoruz. Birisi veri gönderiyor, diğeri veriyi alınca küçük bir “aldım” mesajı gönderiyor. İkisi de şimdilik aynı bilgisayarda.

## 1. Alıcıyı başlat

Python 3.10 veya üstü gerekir. Repo klasöründe terminal aç:

```sh
python tunnelscope.py receive
```

`Listening on 127.0.0.1:9471` görmelisin. Bu, kendi bilgisayarındaki 9471 numaralı UDP portunun dinlendiğini söyler. Alıcı varsayılan olarak 30 saniye veri gelmezse kapanır; gerekirse tekrar başlat.

## 2. Başka terminalden veri gönder

Aynı repo klasöründe ikinci terminal aç:

```sh
python tunnelscope.py probe 127.0.0.1 --sizes 64,512,1200,1400 --count 3 --output report.json
```

Burada dört farklı büyüklükte veri gönderiyoruz. Her büyüklüğü üç kere deniyoruz: toplam 12 deneme.

- `127.0.0.1`: bu bilgisayarın kendisi.
- `--sizes`: UDP verisinin boyutu, bayt olarak. Programın kendi 24 baytlık başlığı dahil; IP ve UDP başlıkları hariç.
- `--count 3`: her boyut için üç deneme.
- `--output report.json`: sonuçları dosyaya yaz.

## 3. Sonucu oku

`results` içindeki her kayıt bir denemedir:

- `acknowledged`: veri alıcıya gitti, küçük onay cevabı geri geldi.
- `timeout`: süre dolana kadar doğru onay cevabı gelmedi. Nedenini henüz bilmiyoruz.
- `socket_error`: işletim sistemi bir soket hatası bildirdi; mesaj `error` alanında.
- `rtt_ms`: gönderimden onay cevabına kadar geçen yaklaşık süre. Bu tek yön gecikmesi değildir.

Alıcı gelen verinin tamamını geri göndermez. Bu yüzden iki yönde aynı boyutun geçtiğini iddia edemeyiz.

## Bu adımın sınırı

Henüz MTU ölçmüyoruz. İşletim sistemi büyük UDP verisini parçalara bölebilir. Büyük bir verinin ulaşması, aynı boyuttaki tek bir IP paketinin bütün yolu geçebildiğini kanıtlamaz.

Aynı bilgisayardaki bu deneme gerçek VPN veya Kubernetes ağını da test etmez. Yalnızca veri gönderme, alma ve raporlama temelini doğrular.

## Kendin açıkla

Denemeden sonra şu üç soruyu cevapla:

1. Bir UDP denemesi için neden ayrıca onay mesajı yazdık?
2. Onay gelmemesi neden “kesin MTU sorunu” demek değil?
3. `payload_bytes` ile ağdaki IP paketinin boyutu neden aynı değil?

Sonraki adım: Linux laboratuvarında paketlerin parçalanmasını engelleyerek dar bir bağlantının etkisini görmek.
