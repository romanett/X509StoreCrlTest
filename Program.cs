using PInvokeTest;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static System.Formats.Asn1.AsnWriter;
using static System.Net.Mime.MediaTypeNames;


foreach (StoreLocation storeLocation in (StoreLocation[])
            Enum.GetValues(typeof(StoreLocation)))
{
    foreach (StoreName storeName in (StoreName[])
        Enum.GetValues(typeof(StoreName)))
    {
        X509Store store = new X509Store(storeName, storeLocation);

        try
        {
            byte[][] crls = store.EnumerateCrls();

            foreach (byte[] crl2 in crls)
            {
                Console.WriteLine("crl: " + Encoding.Default.GetString(crl2) + "\n");

                Console.WriteLine("Trying to add crl to store: ");

                store.AddCrl(crl2);
            }
            store.Close();
        }
        catch (CryptographicException e)
        {
            //Console.WriteLine("Store {0} failed to open on {1} " + e.Message,
            //    store.Name, store.Location);
        }
    }
    Console.WriteLine();
}

X509Store CaStore = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser);

try
{
    var myCrl = File.ReadAllBytes("Test.crl");
    Console.WriteLine(Encoding.Default.GetString(myCrl));
    //CaStore.AddCrl(myCrl);
    CaStore.DeleteCrl(myCrl);
}
catch (CryptographicException e)
{
    Console.WriteLine("Store CertificateAuthority failed to open on LocalMachine " + e.Message);
}
