using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace PInvokeTest
{


    public static class X509StoreExtensions
    {
        public static byte[][] EnumerateCrls(this X509Store store)
        {
            if (!store.IsOpen)
            {
                store.Open(OpenFlags.OpenExistingOnly);
                Console.WriteLine("Store " + store.Name + " on " + store.Location + " opened with " +
               store.Certificates.Count + " Certificates" + "\n");
            }

            IntPtr handle = store.StoreHandle;

            return CrlEnumerationHelper.GetCrls(handle);
        }


        public static void AddCrl(this X509Store store, byte[] crl)
        {
            if (!store.IsOpen)
            {
                store.Open(OpenFlags.OpenExistingOnly);
                Console.WriteLine("Store " + store.Name + " on " + store.Location + " opened with " +
               store.Certificates.Count + " Certificates" + "\n");
            }

            IntPtr handle = store.StoreHandle;

            AddDeleteCrlHelper.AddCrl(handle, crl);
        }

        public static void DeleteCrl(this X509Store store, byte[] crl)
        {
            if (!store.IsOpen)
            {
                store.Open(OpenFlags.OpenExistingOnly);
                Console.WriteLine("Store " + store.Name + " on " + store.Location + " opened with " +
               store.Certificates.Count + " Certificates" + "\n");
            }

            IntPtr handle = store.StoreHandle;

            AddDeleteCrlHelper.DeleteCrl(handle, crl);
        }
    }
}
