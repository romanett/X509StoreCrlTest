using System;
using System.Runtime.InteropServices;
using Windows.Win32;
using Windows.Win32.Security.Cryptography;

namespace PInvokeTest
{
    internal static unsafe class AddDeleteCrlHelper
    {
        public static void AddCrl(IntPtr storeHandle, byte[] crl)
        {
            if ((RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) && OperatingSystem.IsOSPlatformVersionAtLeast("Windows", 5, 1, 2600))
            {
                IntPtr rawCrl = Marshal.AllocHGlobal(crl.Length);

                Marshal.Copy(crl, 0, rawCrl, crl.Length);

                //CERT_STORE_ADD_REPLACE_EXISTING
                if (PInvoke.CertAddEncodedCRLToStore((HCERTSTORE)storeHandle.ToPointer(), CERT_QUERY_ENCODING_TYPE.PKCS_7_ASN_ENCODING, (byte*)rawCrl, (uint)crl.Length, 0, null))
                {
                    Console.WriteLine("Sucessfully added crl to store");
                    return;
                }
                else
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error != 0)
                        Console.WriteLine("Errorcode from CertAddEncodedCRLToStore: " + error);
                    return;
                }
            }
        }

        public static void DeleteCrl(IntPtr storeHandle, byte[] crl)
        {
            throw new NotImplementedException();
            if ((RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) && OperatingSystem.IsOSPlatformVersionAtLeast("Windows", 5, 1, 2600))
            {
                CrlEnumerationHelper.GetCrls(storeHandle);

                //PInvoke.CertDeleteCRLFromStore()

                //IntPtr rawCrl = Marshal.AllocHGlobal(crl.Length);

                //Marshal.Copy(crl, 0, rawCrl, crl.Length);
            }
        }
    }
}
