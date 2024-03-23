using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Windows.Win32;
using Windows.Win32.Security.Cryptography;

namespace PInvokeTest
{

    internal static unsafe class CrlEnumerationHelper
    {
        public static byte[] GetCrl(IntPtr storeHandle)
        {
            try
            {
                //SupportedOSPlatform("windows5.1.2600")
                if ((RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) && OperatingSystem.IsOSPlatformVersionAtLeast("Windows", 5, 1, 2600))
                {
                    CRL_CONTEXT* crlContext = PInvoke.CertEnumCRLsInStore((HCERTSTORE)storeHandle.ToPointer(), (CRL_CONTEXT*)IntPtr.Zero);

                    if (crlContext is null)
                    {
                        Console.WriteLine("crlContext is null");
                        return [];
                    }

                    uint length = 0;

                    if (!PInvoke.CertSerializeCRLStoreElement(*crlContext, 0, null, ref length))
                    {
                        Console.WriteLine("CertSerializeCRLStoreElement returned an error");
                        return [];
                    }

                    IntPtr Elements = Marshal.AllocHGlobal((int)length);
                    if (!PInvoke.CertSerializeCRLStoreElement(*crlContext, 0, (byte*)Elements, ref length))
                    {
                        Console.WriteLine("CertSerializeCRLStoreElement returned an error on second call");
                        return [];
                    }
                    byte[] crl = new byte[length];
                    Marshal.Copy(Elements, crl, 0, (int)length); // Copy data from unmanaged memory to managed array

                    Marshal.FreeHGlobal(Elements);

                    PInvoke.CertFreeCRLContext(crlContext);

                    return crl;
                }
                return [];
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("Failed with:" + e);
                return [];
            }
        }

        public static byte[][] GetCrls(IntPtr storeHandle)
        {
            List<byte[]> crls = [];
            try
            {
                //SupportedOSPlatform("windows5.1.2600")
                if ((RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) && OperatingSystem.IsOSPlatformVersionAtLeast("Windows", 5, 1, 2600))
                {

                    CRL_CONTEXT* crlContext = (CRL_CONTEXT*)IntPtr.Zero;
                    while (true){
                        crlContext = PInvoke.CertEnumCRLsInStore((HCERTSTORE)storeHandle.ToPointer(), crlContext);

                        if (crlContext != null)
                        {
                            byte[] crl = ReadCrlFromCrlContext(crlContext);

                            if (crl != null)
                            {
                                crls.Add(crl);
                            }
                        }
                        else
                        {
                            var error = Marshal.GetLastWin32Error(); 
                            if (error == -2146885628)
                            {
                                Console.WriteLine("No more crls found in store");
                            }
                            else if(error != 0)
                                Console.WriteLine("Errorcode from CertEnumCRLsInStore: " + error);
                            break;
                        }
                    }
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("Failed with:" + e);

            }
            return crls.ToArray();
        }

        public static byte[] ReadCrlFromCrlContext(CRL_CONTEXT* crlContext)
        {
            if ((RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) && OperatingSystem.IsOSPlatformVersionAtLeast("Windows", 5, 1, 2600))
            {
                uint length = 0;

                if (!PInvoke.CertSerializeCRLStoreElement(*crlContext, 0, null, ref length))
                {
                    Console.WriteLine("CertSerializeCRLStoreElement returned an error");
                    return [];
                }

                IntPtr Elements = Marshal.AllocHGlobal((int)length);
                if (!PInvoke.CertSerializeCRLStoreElement(*crlContext, 0, (byte*)Elements, ref length))
                {
                    Console.WriteLine("CertSerializeCRLStoreElement returned an error on second call");
                    return [];
                }
                byte[] crl = new byte[length];
                Marshal.Copy(Elements, crl, 0, (int)length); // Copy data from unmanaged memory to managed array

                Marshal.FreeHGlobal(Elements);

                return crl;
            }
            return [];
        }
    }
}


