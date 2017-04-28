using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace MobileLife.OBCO.Data.Signicat
{
    public class CryptoUtils
    {
        private const string RsaPrivateKeyHeader = "-----BEGIN RSA PRIVATE KEY-----";
        private const string RsaPrivateKeyFooter = "-----END RSA PRIVATE KEY-----";
        private const string CertificateHeader = "-----BEGIN CERTIFICATE-----";
        private const string CertificateFooter = "-----END CERTIFICATE-----";

        public static X509Certificate2 CreateX509Certificate2FromCertificateAndPrivateKeyPems(string certificatePem, string privateKeyPem)
        {
            var certificate = CreateX509Certificate2FromCertificatePem(certificatePem);
            var privatekey = CreateRsaProviderFromPrivatePemKey(privateKeyPem);
            certificate.PrivateKey = privatekey;
            return certificate;
        }

        public static X509Certificate2 CreateX509Certificate2FromCertificatePem(string certificatePem)
        {
             // Extract base64 formated key
            var base64KeyStart = certificatePem.IndexOf(CertificateHeader, StringComparison.Ordinal);
            var base64KeyEnd = certificatePem.LastIndexOf(CertificateFooter, StringComparison.Ordinal);
            if (base64KeyStart < 0 || base64KeyEnd < 200) // TODO: Find better number
            {
                throw new Exception("Not a valied pem formated certificate");
            }
            var start = base64KeyStart + CertificateHeader.Length;
            var length = base64KeyEnd - start;
            var base64PemCertificate = Regex.Replace(certificatePem.Substring(start, length), @"\r\n?|\n", "");
            return new X509Certificate2(Convert.FromBase64String(base64PemCertificate));
        }


        public static RSACryptoServiceProvider CreateRsaProviderFromCertificate(string subjectName, HashAlgorithm hashAlgorithmRequired = null)
        {
            X509Store localMachineStore = null;
            try
            {
                localMachineStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                localMachineStore.Open(OpenFlags.ReadOnly);
                var certs = localMachineStore.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, subjectName, false);
                if (certs.Count > 0)
                {
                    if (certs[0].HasPrivateKey)
                    {
                        RSACryptoServiceProvider rsaCryptoServiceProvider;
                        try
                        {
                            rsaCryptoServiceProvider = (RSACryptoServiceProvider) certs[0].PrivateKey;

                            // Try to sign some data with the hash algorithm to find out if it is supported
                            if (hashAlgorithmRequired != null)
                            {
                                rsaCryptoServiceProvider.SignData(new byte[16], hashAlgorithmRequired);
                            }
                        }
                        catch (CryptographicException ex)
                        {
                            if (ex.Message.StartsWith("Invalid algorithm specified"))
                            {
                                // Extract privat key and reimport it to get rid of sha1 signing limitation on some keys
                                rsaCryptoServiceProvider = new RSACryptoServiceProvider();
                                rsaCryptoServiceProvider.FromXmlString(certs[0].PrivateKey.ToXmlString(true));
                                rsaCryptoServiceProvider.SignData(new byte[16], hashAlgorithmRequired);
                            }
                            else
                            {
                                throw ex;
                            }
                        }
                        return rsaCryptoServiceProvider;
                    }
                    else
                    {
                        throw new CryptoUtilsException("Selected certificat does not a have private key");
                    }

                }
                else
                {
                    throw new CryptoUtilsException("No certificate found with this subject name");
                }
            }
            finally
            {
                localMachineStore?.Close();
            }
        }


        public static RSACryptoServiceProvider CreateRsaProviderFromPrivatePemKey(string pemPrivateKey)
        {
            // Extract base64 formated key
            var base64KeyStart = pemPrivateKey.IndexOf(RsaPrivateKeyHeader, StringComparison.Ordinal);
            var base64KeyEnd = pemPrivateKey.LastIndexOf(RsaPrivateKeyFooter, StringComparison.Ordinal);
            if (base64KeyStart < 0 || base64KeyEnd < 200) // TODO: Find better number
            {
                throw new Exception("Not a valied pem formated private key");
            }
            var start = base64KeyStart + RsaPrivateKeyHeader.Length;
            var length = base64KeyEnd - start;
            var base64PemPrivateKey = Regex.Replace(pemPrivateKey.Substring(start, length), @"\r\n?|\n", "");

            // Convert to RSACryptoServiceProvider
            var privateKeyBits = Convert.FromBase64String(base64PemPrivateKey);
            var cspPrms = new CspParameters
            {
                KeyContainerName = $"{Guid.NewGuid():N}", // Generate random name for key container
                Flags = CspProviderFlags.UseMachineKeyStore
            };
            var rsa = new RSACryptoServiceProvider(cspPrms) {PersistKeyInCsp = false};
            var rsaParameters = new RSAParameters();

            using (var binaryReader = new BinaryReader(new MemoryStream(privateKeyBits)))
            {
                byte bt = 0;
                ushort twobytes = 0;
                twobytes = binaryReader.ReadUInt16();
                if (twobytes == 0x8130)
                {
                    binaryReader.ReadByte();
                }
                else if (twobytes == 0x8230)
                {
                    binaryReader.ReadInt16();
                }
                else
                {
                    throw new CryptoUtilsException("Unexpected value read binr.ReadUInt16()");
                }

                twobytes = binaryReader.ReadUInt16();
                if (twobytes != 0x0102)
                {
                    throw new CryptoUtilsException("Unexpected version");
                }

                bt = binaryReader.ReadByte();
                if (bt != 0x00)
                {
                    throw new CryptoUtilsException("Unexpected value read binr.ReadByte()");
                }

                rsaParameters.Modulus = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.Exponent = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.D = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.P = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.Q = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.DP = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.DQ = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.InverseQ = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
            }

            rsa.ImportParameters(rsaParameters);
            return rsa;
        }

        private static int GetIntegerSize(BinaryReader binr)
        {
            byte bt = 0;
            int count = 0;
            bt = binr.ReadByte();
            if (bt != 0x02)
            {
                return 0;
            }
            bt = binr.ReadByte();

            if (bt == 0x81)
            {
                count = binr.ReadByte();
            }
            else if (bt == 0x82)
            {
                var highByte = binr.ReadByte();
                var lowByte = binr.ReadByte();
                byte[] modint = { lowByte, highByte, 0x00, 0x00 };
                count = BitConverter.ToInt32(modint, 0);
            }
            else
            {
                count = bt;
            }
            while (binr.ReadByte() == 0x00)
            {
                count -= 1;
            }
            binr.BaseStream.Seek(-1, SeekOrigin.Current);
            return count;
        }

        public static X509Certificate2 GetSignerCertificate(X509Certificate2 rootCertificate, List<X509Certificate2> certificates, DateTimeOffset? signatureTime)
        {
            var certificateChain = new X509Chain
            {
                ChainPolicy =
                {
                    RevocationMode = X509RevocationMode.NoCheck,
                    VerificationFlags = X509VerificationFlags.IgnoreWrongUsage,
                    RevocationFlag = X509RevocationFlag.ExcludeRoot
                }
            };

            // Add root certificate
            certificateChain.ChainPolicy.ExtraStore.Add(rootCertificate);

            // Extract all certificates from signature
            X509Certificate2 signerCertificate = null;
            foreach (var certificate in certificates)
            {
                var keyUsage = (certificate?.Extensions["2.5.29.15"] as X509KeyUsageExtension)?.KeyUsages.ToString();
                if (keyUsage != null && (keyUsage.Contains("DigitalSignature") || keyUsage.Contains("NonRepudiation")) && !keyUsage.Contains("CrlSign"))
                {
                    signerCertificate = certificate;

                }
                else if (certificate != null && !certificate.Equals(rootCertificate))
                {
                    certificateChain.ChainPolicy.ExtraStore.Add(certificate);
                }
            }

            if (signerCertificate == null)
            {
                throw new XmlSignatureVerificationException("Did not find signer certificate");
            }

            // Validation might fail if we have not imported the root certificate to windows certificate store, so here we validate the chain ourself
            certificateChain.Build(signerCertificate);

            foreach (var status in certificateChain.ChainStatus)
            {
                if (status.Status == X509ChainStatusFlags.UntrustedRoot)
                {
                    // Allow UntrustedRoot as it will also be marked on the found root certificate

                } else if (status.Status == X509ChainStatusFlags.NotTimeValid)
                {
                    // Allow NotTimeValid as it will also be marked on the found certificate with the issue
                }
                else
                {
                    throw new XmlSignatureVerificationException($"Unknown issue with certificate chain {status.Status}: {status.StatusInformation}");
                }
            }

            var certificateRootChainElement = certificateChain.ChainElements[certificateChain.ChainElements.Count - 1];
            if (!certificateRootChainElement.Certificate.Equals(rootCertificate))
            {
                throw new XmlSignatureVerificationException("Root certificate does not match defined root");
            }

            // If we have a validation error, only allow it to be UntrustedRoot validation because certificates are not installed
            if (certificateRootChainElement.ChainElementStatus.Length > 0 && certificateRootChainElement.ChainElementStatus[0].Status != X509ChainStatusFlags.UntrustedRoot)
            {
                throw new XmlSignatureVerificationException("Certificate chain does not validate: " + certificateChain.ChainStatus[0].StatusInformation);
            }

            // TryValidate the rest of the certificates and also handle that they could have expired
            for (var i = 0; i < certificateChain.ChainElements.Count - 1; i++)
            {
                var chainElement = certificateChain.ChainElements[i];

                foreach (var status in chainElement.ChainElementStatus)
                {
                    if (status.Status == X509ChainStatusFlags.NotTimeValid && signatureTime != null && signatureTime <= chainElement.Certificate.NotAfter && signatureTime >= chainElement.Certificate.NotBefore)
                    {
                        // Signature was done within the allowed timespan
                    }
                    else
                    {
                        throw new XmlSignatureVerificationException("Validation failed");
                    }
                }
            }

            if (signatureTime != null && (signatureTime < signerCertificate.NotBefore || signatureTime > signerCertificate.NotAfter))
            {
                throw new XmlSignatureVerificationException("Document signed outside signer certificate validity");
            }

            return signerCertificate;
        }
    }
    public class CryptoUtilsException : Exception
    {
        public CryptoUtilsException() { }
        public CryptoUtilsException(string message) : base(message) { }
        public CryptoUtilsException(string message, Exception inner) : base(message, inner) { }
    }
}