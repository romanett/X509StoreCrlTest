using PInvokeTest;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;


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
            Console.WriteLine("Store {0} failed to open on {1} " + e.Message,
                store.Name, store.Location);
        }
    }
    Console.WriteLine();
}

