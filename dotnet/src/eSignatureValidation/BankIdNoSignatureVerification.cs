using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace MobileLife.OBCO.Data.Signicat
{
    public class BankIdNoSignatureVerification
    {
        private static readonly X509Certificate2 SystemTestBankIdSeRootCertificate = new X509Certificate2(Convert.FromBase64String(
            "MIIF0jCCA7qgAwIBAgIISpGbuE9LL/0wDQYJKoZIhvcNAQENBQAwbTEkMCIGA1UE\nCgwbRmluYW5zaWVsbCBJRC1UZWtuaWsgQklEIEFCMR8wHQYDVQQLDBZCYW5rSUQg\nTWVtYmVyIEJhbmtzIENBMSQwIgYDVQQDDBtUZXN0IEJhbmtJRCBSb290IENBIHYx\nIFRlc3QwHhcNMTEwOTIyMTQwMTMzWhcNMzQxMjMxMTQwMTMzWjBtMSQwIgYDVQQK\nDBtGaW5hbnNpZWxsIElELVRla25payBCSUQgQUIxHzAdBgNVBAsMFkJhbmtJRCBN\nZW1iZXIgQmFua3MgQ0ExJDAiBgNVBAMMG1Rlc3QgQmFua0lEIFJvb3QgQ0EgdjEg\nVGVzdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANPXoOB9BQOW8i2C\nKk7U/d8rFNB0ktVlcgBSh8CKvnTsW3i+NrAM5LY9jgAO9vkHT3bl3nK626zePhmh\ndhVXMKAanbcF/NJ/oSF+DKCGx/VgPmCCqVyTMLjID/59diiLg3xNH3NaaBM69qnw\n5yOCYkB2wXxcATLO0eTxvL0vdKGJ2HU2AcEtaMMxrScuNCztPuwjYNP0KrYI+y/J\nGkf2dBhomAhDLdQSSW3zXqYgbQvJ8La2ECgo3rGQQRZG9/5MZ5dOWtpAx0ybeCbh\nCPO8XIBCHrPZxv60gZK1CTwlZUoMTBSivv+vmFrH8JdmUnOP9e/wNhuM9/fQ0h5t\n4BGXoz8M5nxdH6uNJG5SpdxaXYflezBb7YdjgNiF9Yqo3DYTRrZT7dyRLYqlmKQh\nT1pqEov1tkXktQF8r1QJkTJO3x1QEzMNCnHyN8iDOqENSE4nhkzU9ESbXNOhFpnc\nXJqoFwvbeAJpV7fVwn+Jumyc/zsD9t+1Vo1lM95q1geVPfnA5z7NZ+uaayJx4DhL\nMvufDI17fqgiWHe+BMA/vGd8OjFK3JUmCV+7QeG/Z3JWbzU0GeDljqO+H4CQ0+LO\n4E4JGEZtxfUu4/XuOkCqiZ4/shoPOOxaXcZlBEMHsDzei0tNSKIxB+PoDTje/BQC\nlunVZvjcG2ehpeF540EXgzzECaNLAgMBAAGjdjB0MB0GA1UdDgQWBBRK96NqCNoI\nOBcZUyjI2qbWNNhaujAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFEr3o2oI\n2gg4FxlTKMjaptY02Fq6MBEGA1UdIAQKMAgwBgYEKgMEBTAOBgNVHQ8BAf8EBAMC\nAQYwDQYJKoZIhvcNAQENBQADggIBAJVcP9Sm2tukKW0Qx8EZG9gdXfCmNMrHXF3g\nvia5zpuSMl9wdXHd1FPdGFshRZJ2sW4mb9vRI81vBIXMFVtLZFzeGHoKyz1g8hfj\nuuLKpItw0OwVNdvSRq/TKKxjVKpvt50Eydgnz4Q59YkFlGVyi7+z74mGfvN06Ssj\n2WIRtr3UD+IC6Tie6Lm/zuZs4gu0ZP/fddKh7gC3syHLNXQmN+9Y0wkdO7H98K/9\nuuIrxWtSOFVatxesw7XJRnq+uYI0IdP8xP8U4S680rTse7nsTguQxzRs2vOyoaXm\nFdf7XQ03btd15Z4yJlEfs9/4ohgafMs49PMkACqyX45/4WBygO0QwMGVIUnKNFBt\n/I+0T2SkWFa2JdcRCSTObb7tesoeTIPgI9UcrMvNOG3gxGpB/H5/s7jTV0AOoDgM\nhOxieGgyTsZ3oP0k6bc47FJ4nE+vifAluyeXioB5JaN2kvm8eqfzC05zSF40V9GA\nzElVDbsBPR/2CE6CMyR+eqip4gDSZ6mnZYPeBecEXU4Xu+RAgqYxjKosfxOpMZsN\n+2BSm5QSRLhHacPQTnoQxujnGuUzh5TdAbWqmS0cKEZJ+CACmVLyOphdRoeEQCqQ\n8DYAyOtq2S4+hAJW+2Xq4NCdvmjm99r2RFkibSlLtqctj1JyzUC6huUiQXx9KZ8n\nFA0TsFHG\n"
        ));

        public BankIdNoSignatureVerification(string xml) : this(new MemoryStream(Encoding.UTF8.GetBytes(xml)))
        {
        }

        public BankIdNoSignatureVerification(Stream xmlStream)
        {
            var reader = XmlReader.Create(xmlStream, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                MaxCharactersFromEntities = 30,
                XmlResolver = null
            });
            var doc = new XmlDocument {PreserveWhitespace = true};
            doc.Load(reader);

            var nm = new XmlNamespaceManager(doc.NameTable);
            nm.AddNamespace("sdo", "http://www.npt.no/seid/xmlskjema/SDO_v1.0");
            nm.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            nm.AddNamespace("xsi", "http://www.w3.org/2001/XMLSchema-instance");
            nm.AddNamespace("xades", "http://uri.etsi.org/01903/v1.2.2#");

            var node = doc.SelectSingleNode("//sdo:SDOList/sdo:SDO/sdo:SignedObject/sdo:SignersDocument", nm);
            if (node == null)
            {
                throw new Exception("Cannot find SignersDocument node in SDO");
            }

            var documentContentInfo = new ContentInfo(Convert.FromBase64String(node.InnerText));

            var list = doc.SelectNodes("//sdo:SDOList/sdo:SDO/sdo:SDODataPart/sdo:SignatureElement", nm);
            foreach (XmlNode item in list)
            {
                var cms = new SignedCms(documentContentInfo, true);

                var signatureNode = item.SelectSingleNode("//sdo:CMSSignatureElement/sdo:CMSSignature", nm);
                if (signatureNode != null)
                {
                    cms.Decode(Convert.FromBase64String(signatureNode.InnerText));
                }

                var timeStamp = cms.SignerInfos[0]
                    .SignedAttributes.Cast<CryptographicAttributeObject>()
                    .Where(sa => sa.Oid.Value == "1.2.840.113549.1.9.5" &&
                                 (sa.Oid.FriendlyName.Equals("Signing Time") ||
                                  sa.Oid.FriendlyName.Equals("Tidspunkt for signatur")))
                    .Select(sa => ((Pkcs9SigningTime) sa.Values[0]).SigningTime)
                    .Cast<DateTime?>()
                    .FirstOrDefault();

                // TODO: Validate certificate chain when we get the root certificate
                //var signedCertificate = CryptoUtils.GetSignerCertificate(SystemTestBankIdSeRootCertificate, cms.Certificates.Cast<X509Certificate2>().ToList(), timeStamp);

                cms.CheckHash();
                cms.CheckSignature(true);
            }
        }

        public bool ValidateSignature(DateTimeOffset? signatureTime = null)
        {
            return false;
        }

        public bool TryValidateSignature(DateTimeOffset? signatureTime = null, bool testing = false)
        {
            try
            {
                return false;
                //return ValidateSignature(signatureTime, testing);
            }
            catch(Exception)
            {
                return false;
            }
        }
    }

    [Serializable]
    public class BankIdNoSignatureVerificationException : Exception
    {
        public BankIdNoSignatureVerificationException() { }
        public BankIdNoSignatureVerificationException(string message) : base(message) { }
        public BankIdNoSignatureVerificationException(string message, Exception inner) : base(message, inner) { }
    }
}