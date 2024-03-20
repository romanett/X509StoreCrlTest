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
            store.Open(OpenFlags.OpenExistingOnly);

            Console.WriteLine("Store "+ store.Name+ " on "+ store.Location + " opened with " +
                store.Certificates.Count + " Certificates" + "\n");

            IntPtr handle = store.StoreHandle;

            //byte[] crl = CrlEnumerationHelper.GetCrl(handle);

            //Console.WriteLine("crl: " + Encoding.Default.GetString(crl) + "\n");

            byte[][] crls = CrlEnumerationHelper.GetCrls(handle);

            foreach (byte[] crl2 in crls)
            {
                Console.WriteLine("crl: " + Encoding.Default.GetString(crl2) + "\n");

                Console.WriteLine("Trying to add crl to store: ");

                AddDeleteCrlHelper.AddCrl(handle, crl2);
            }
            store.Close();
        }
        catch (CryptographicException)
        {
            Console.WriteLine("Store {0} failed to open on {1}",
                store.Name, store.Location);
        }
    }
    Console.WriteLine();
}

