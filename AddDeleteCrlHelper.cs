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

                /////+-------------------------------------------------------------------------
                // Add certificate/CRL, encoded, context or element disposition values.
                //--------------------------------------------------------------------------
                //#define CERT_STORE_ADD_NEW                                  1
                //#define CERT_STORE_ADD_USE_EXISTING                         2
                //#define CERT_STORE_ADD_REPLACE_EXISTING                     3
                //#define CERT_STORE_ADD_ALWAYS                               4
                //#define CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES  5
                //#define CERT_STORE_ADD_NEWER                                6
                //#define CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES             7
                if (PInvoke.CertAddEncodedCRLToStore((HCERTSTORE)storeHandle.ToPointer(), CERT_QUERY_ENCODING_TYPE.PKCS_7_ASN_ENCODING, (byte*)rawCrl, (uint)crl.Length, 3, null))
                {
                    Console.WriteLine("Sucessfully added crl to store");
                    return;
                }
                else
                {
                    var error = Marshal.GetLastWin32Error();
                    if(error == -2147024809)
                    {
                        Console.WriteLine("Errorcode from CertAddEncodedCRLToStore: ERROR_INVALID_PARAMETER, The parameter is incorrect. " + error);
                        return;
                    }
                    if (error != 0)
                        Console.WriteLine("Errorcode from CertAddEncodedCRLToStore: " + error);
                    return;
                }
            }
        }

        public static void DeleteCrl(IntPtr storeHandle, byte[] crl)
        {
            if ((RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) && OperatingSystem.IsOSPlatformVersionAtLeast("Windows", 5, 1, 2600))
            {
                CRL_CONTEXT* crlContext = (CRL_CONTEXT*)IntPtr.Zero;
                while (true)
                {
                    crlContext = PInvoke.CertEnumCRLsInStore((HCERTSTORE)storeHandle.ToPointer(), crlContext);

                    if (crlContext != null)
                    {
                        byte[] storeCrl = CrlEnumerationHelper.ReadCrlFromCrlContext(crlContext);

                        
                        if (crl != null && crl.SequenceEqual(storeCrl))
                        {
                            if (!PInvoke.CertDeleteCRLFromStore(crlContext))
                            {
                                var error = Marshal.GetLastWin32Error();
                                if (error != 0)
                                    Console.WriteLine("Errorcode from CertDeleteCRLFromStore: " + error);
                            }
                        }
                    }
                    else
                    {
                        var error = Marshal.GetLastWin32Error();
                        if (error != 0)
                            Console.WriteLine("Errorcode from CertEnumCRLsInStore: " + error);
                        break;
                    }
                }
            }
        }
    }
}
