using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;

public class Sample
{
    public void Run()
    {
        var rsa = new RSACryptoServiceProvider(1024);
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var md5 = MD5.Create();
        var hmac = new HMACSHA1(key);
        var des = TripleDES.Create();
        des.Mode = CipherMode.ECB;
        var options = new SslClientAuthenticationOptions { EnabledSslProtocols = SslProtocols.Tls11 };
        // var old = SHA1.Create();  (commented out)
        var pq = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
    }
}
