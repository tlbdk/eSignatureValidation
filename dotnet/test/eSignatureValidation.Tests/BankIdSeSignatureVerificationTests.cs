using System;
using System.Security.Cryptography.X509Certificates;
using eSignatureValidation.Tests.Common;
using Xunit;

namespace eSignatureValidation.Tests
{
    public class BankIdSeSignatureVerificationTests
    {
        private static readonly X509Certificate2 SystemTestNemIdRootCertificate = new X509Certificate2(Convert.FromBase64String(
            "MIIGSDCCBDCgAwIBAgIES+pulDANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJESzESMBAGA1UE\r\nChMJVFJVU1QyNDA4MSwwKgYDVQQDEyNUUlVTVDI0MDggU3lzdGVtdGVzdCBWSUkgUHJpbWFyeSBD\r\nQTAeFw0xMDA1MTIwODMyMTRaFw0zNzAxMTIwOTAyMTRaME8xCzAJBgNVBAYTAkRLMRIwEAYDVQQK\r\nEwlUUlVTVDI0MDgxLDAqBgNVBAMTI1RSVVNUMjQwOCBTeXN0ZW10ZXN0IFZJSSBQcmltYXJ5IENB\r\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApuuMpdHu/lXhQ+9TyecthOxrg5hPgxlK\r\n1rpjsyBNDEmOEpmOlK8ghyZ7MnSF3ffsiY+0jA51p+AQfYYuarGgUQVO+VM6E3VUdDpgWEksetCY\r\nY8L7UrpyDeYx9oywT7E+YXH0vCoug5F9vBPnky7PlfVNaXPfgjh1+66mlUD9sV3fiTjDL12GkwOL\r\nt35S5BkcqAEYc37HT69N88QugxtaRl8eFBRumj1Mw0LBxCwl21GdVY4EjqH1Us7YtRMRJ2nEFTCR\r\nWHzm2ryf7BGd80YmtJeL6RoiidwlIgzvhoFhv4XdLHwzaQbdb9s141q2s9KDPZCGcgIgeXZdqY1V\r\nz7UBCMiBDG7q2S2ni7wpUMBye+iYVkvJD32srGCzpWqG7203cLyZCjq2oWuLkL807/Sk4sYleMA4\r\nYFqsazIfV+M0OVrJCCCkPysS10n/+ioleM0hnoxQiupujIGPcJMA8anqWueGIaKNZFA/m1IKwnn0\r\nCTkEm2aGTTEwpzb0+dCATlLyv6Ss3w+D7pqWCXsAVAZmD4pncX+/ASRZQd3oSvNQxUQr8EoxEULx\r\nSae0CPRyGwQwswGpqmGm8kNPHjIC5ks2mzHZAMyTz3zoU3h/QW2T2U2+pZjUeMjYhyrReWRbOIBC\r\nizoOaoaNcSnPGUEohGUyLPTbZLpWsm3vjbyk7yvPqoUCAwEAAaOCASowggEmMA8GA1UdEwEB/wQF\r\nMAMBAf8wDgYDVR0PAQH/BAQDAgEGMBEGA1UdIAQKMAgwBgYEVR0gADCBrwYDVR0fBIGnMIGkMDqg\r\nOKA2hjRodHRwOi8vY3JsLnN5c3RlbXRlc3Q3LnRydXN0MjQwOC5jb20vc3lzdGVtdGVzdDcuY3Js\r\nMGagZKBipGAwXjELMAkGA1UEBhMCREsxEjAQBgNVBAoTCVRSVVNUMjQwODEsMCoGA1UEAxMjVFJV\r\nU1QyNDA4IFN5c3RlbXRlc3QgVklJIFByaW1hcnkgQ0ExDTALBgNVBAMTBENSTDEwHwYDVR0jBBgw\r\nFoAUI7pMMZDh08zTG7MbWrbIRc3Tg5cwHQYDVR0OBBYEFCO6TDGQ4dPM0xuzG1q2yEXN04OXMA0G\r\nCSqGSIb3DQEBCwUAA4ICAQCRJ9TM7sISJBHQwN8xdey4rxA0qT7NZdKICcIxyIC82HIOGAouKb3o\r\nHjIoMgxIUhA3xbU3Putr4+Smnc1Ldrw8AofLGlFYG2ypg3cpF9pdHrVdh8QiERozLwfNPDgVeCAn\r\njKPNt8mu0FWBS32tiVM5DEOUwDpoDDRF27Ku9qTFH4IYg90wLHfLi+nqc2HwVBUgDt3tXU6zK4pz\r\nM0CpbrbOXPJOYHMvaw/4Em2r0PZD+QOagcecxPMWI65t2h/USbyO/ah3VKnBWDkPsMKjj5jEbBVR\r\nnGZdv5rcJb0cHqQ802eztziA4HTbSzBE4oRaVCrhXg/g6Jj8/tZlgxRI0JGgAX2dvWQyP4xhbxLN\r\nCVXPdvRV0g0ehKvhom1FGjIz975/DMavkybh0gzygq4sY9Fykl4oT4rDkDvZLYIxS4u1BrUJJJaD\r\nzHCeXmZqOhx8She+Fj9YwVVRGfxT4FL0Qd3WAtaCVyhSQ6SkZgrPvzAmxOUruI6XhEhYGlP5O8WF\r\nETiATxuZAJNuKMJtibfRhMNsQ+TVv/ZPr5Swe+3DIQtmt1MIlGlTn4k40z4s6gDGKiFwAYXjd/kI\r\nD32R/hJPE41o9+3nd8aHZhBy2lF0jKAmr5a6Lbhg2O7zjGq7mQ3MceNeebuWXD44AxIinryzhqnE\r\nWI+BxdlFaia3U7o2+HYdHw=="
        ));

        private static readonly X509Certificate2 WrongBankIdSeRootCertificate = new X509Certificate2(Convert.FromBase64String(
            "MIIF0zCCA7ugAwIBAgIIUYmfdtqty80wDQYJKoZIhvcNAQENBQAwbTEkMCIGA1UECgwbRmluYW5zaWVsbCBJRC1UZWtuaWsgQklEIEFCMR8wHQYDVQQLDBZCYW5rSUQgTWVtYmVyIEJhbmtzIENBMSQwIgYDVQQDDBtUZXN0IEJhbmtJRCBSb290IENBIHYxIFRlc3QwHhcNMTEwOTIyMTQxNTAzWhcNMzQxMjMxMTQwMTMzWjBuMQswCQYDVQQGEwJTRTEdMBsGA1UECgwUVGVzdGJhbmsgQSBBQiAocHVibCkxFTATBgNVBAUTDDExMTExMTExMTExMTEpMCcGA1UEAwwgVGVzdGJhbmsgQSBDQSB2MSBmb3IgQmFua0lEIFRlc3QwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCTqU7uxk5QzbXS6ArXIGTWNeZXz65bzdgoxb79LvYh/p7kcK25mA2tzGpO3QS1eKJJu84G9UNzm4mMl6cngnXcjxETYiEqtijrA5mfz865/X6UgOpX7DkouQ8d5eDyhJ49UrDqlrgoVMx322kM0SZ4heVeX83e1ISFiyxqZBKxh25yKYEZA4EzIrDj2ti8CRrWPHCTWaIFpcd5TyMhpUTPn4DzwPhPGWMRNxgOAeP4BSDB7R6az4rox7TPkd2sWG1ODj/0IRPhJS1dQ1B7QiNHY58RjnNThEQKwdWWMPMKPthSd+GEjL9GDafYxOsIrKFYwlYNBW3C5mbe3T+3j+Axj6W2HbgmJXPGItLucxY1kPwT9L7u5nIxaROmh1uTwYqr9puGq6soJnggES3K4PIhM6kamvnCCPXoqWCCruSEPVgyEZEi0shy+81Qseb1gc9rYgVrEnLBOIyMqaTtExaFprYbv1f/AwWtjFUi2XiSdN8aMp+kqbi+1tKJUUPLC+Crdu9fFo/8lslSdew+SnPVFeVz5COKbt6GTE4xcJeRzW5wQ0w7b+rGLWhJvwRJsS5GXvqa3Lg8EyWiLJswuTFaEwPUDvZBvyFZEZertKgZbRYvezo9/grwyB+morVrLryu9chYEYwE550uzyKtzXUzygV8FpXe9DpmpOSfGMAURQIDAQABo3YwdDAdBgNVHQ4EFgQUo/J4eR0rRYrJ4cqVCeWeb87LTsUwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRK96NqCNoIOBcZUyjI2qbWNNhaujARBgNVHSAECjAIMAYGBCoDBAUwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBDQUAA4ICAQDP1DoxjEjeyG27xeai+mpxxJoqB1RDVTEY86RdNyluUKQOIbfKJMmX+DX4vTuUQS3539xzHKwpj6gk+iZVjF1UoJtGp+qurjjarOh44s++s0yWKiKrJBEloJn8o+YXFT8C7e1WtqJVoaFdDBCvohJyK20PKS7/nUG5b7J6iq3517Yvjb4D94Lt0dHNSgD2BIIHmNkpSYWgyi1seavhN5AjtfJr4p101u2SsNcLAr42A5fran9vL29HjaM2MTU8L0OxoIX8lgcpUy9wci7lHQKOiwaOcIKfCC1qM7lO5z0c4P+o0zT6183xJV3rmw22GGYd40EBqW97oqBK0Ij+Kl5suycZ4J2qK1aVciYBZsBNlbtmz/k8HuBxy9WbEePsY/61I50fBLSAkVk/Tea4j+NNHJ1imp7Bo18aLo8plb9e2iZeIDzH1u66o0RFYbHdnJD8CnPeBLVgSvEqmBS11fgHr81/tk5lJxcKejdsEftzGQxwuHw/pjkjobIkxrroXpa6iXokVyH4be16+f/dDaEkh9Rf8Lh1UEQPxxpCyISMifH5pL78DKhGnh8Vfi7EesUV1k6Y3eVCFw2CCKWcvXsJb9QqLFsDqIlWPh6bBgM4aXfpe0arDrgYRbbx8L6ouhyxAHwjtz9i0lXezWMX5f7QYREMTC5yBPNTTP2fCNsozQ=="
        ));

        private static readonly X509Certificate2 SystemTestBankIdSeRootCertificate = new X509Certificate2(Convert.FromBase64String(
            "MIIF0jCCA7qgAwIBAgIISpGbuE9LL/0wDQYJKoZIhvcNAQENBQAwbTEkMCIGA1UE\nCgwbRmluYW5zaWVsbCBJRC1UZWtuaWsgQklEIEFCMR8wHQYDVQQLDBZCYW5rSUQg\nTWVtYmVyIEJhbmtzIENBMSQwIgYDVQQDDBtUZXN0IEJhbmtJRCBSb290IENBIHYx\nIFRlc3QwHhcNMTEwOTIyMTQwMTMzWhcNMzQxMjMxMTQwMTMzWjBtMSQwIgYDVQQK\nDBtGaW5hbnNpZWxsIElELVRla25payBCSUQgQUIxHzAdBgNVBAsMFkJhbmtJRCBN\nZW1iZXIgQmFua3MgQ0ExJDAiBgNVBAMMG1Rlc3QgQmFua0lEIFJvb3QgQ0EgdjEg\nVGVzdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANPXoOB9BQOW8i2C\nKk7U/d8rFNB0ktVlcgBSh8CKvnTsW3i+NrAM5LY9jgAO9vkHT3bl3nK626zePhmh\ndhVXMKAanbcF/NJ/oSF+DKCGx/VgPmCCqVyTMLjID/59diiLg3xNH3NaaBM69qnw\n5yOCYkB2wXxcATLO0eTxvL0vdKGJ2HU2AcEtaMMxrScuNCztPuwjYNP0KrYI+y/J\nGkf2dBhomAhDLdQSSW3zXqYgbQvJ8La2ECgo3rGQQRZG9/5MZ5dOWtpAx0ybeCbh\nCPO8XIBCHrPZxv60gZK1CTwlZUoMTBSivv+vmFrH8JdmUnOP9e/wNhuM9/fQ0h5t\n4BGXoz8M5nxdH6uNJG5SpdxaXYflezBb7YdjgNiF9Yqo3DYTRrZT7dyRLYqlmKQh\nT1pqEov1tkXktQF8r1QJkTJO3x1QEzMNCnHyN8iDOqENSE4nhkzU9ESbXNOhFpnc\nXJqoFwvbeAJpV7fVwn+Jumyc/zsD9t+1Vo1lM95q1geVPfnA5z7NZ+uaayJx4DhL\nMvufDI17fqgiWHe+BMA/vGd8OjFK3JUmCV+7QeG/Z3JWbzU0GeDljqO+H4CQ0+LO\n4E4JGEZtxfUu4/XuOkCqiZ4/shoPOOxaXcZlBEMHsDzei0tNSKIxB+PoDTje/BQC\nlunVZvjcG2ehpeF540EXgzzECaNLAgMBAAGjdjB0MB0GA1UdDgQWBBRK96NqCNoI\nOBcZUyjI2qbWNNhaujAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFEr3o2oI\n2gg4FxlTKMjaptY02Fq6MBEGA1UdIAQKMAgwBgYEKgMEBTAOBgNVHQ8BAf8EBAMC\nAQYwDQYJKoZIhvcNAQENBQADggIBAJVcP9Sm2tukKW0Qx8EZG9gdXfCmNMrHXF3g\nvia5zpuSMl9wdXHd1FPdGFshRZJ2sW4mb9vRI81vBIXMFVtLZFzeGHoKyz1g8hfj\nuuLKpItw0OwVNdvSRq/TKKxjVKpvt50Eydgnz4Q59YkFlGVyi7+z74mGfvN06Ssj\n2WIRtr3UD+IC6Tie6Lm/zuZs4gu0ZP/fddKh7gC3syHLNXQmN+9Y0wkdO7H98K/9\nuuIrxWtSOFVatxesw7XJRnq+uYI0IdP8xP8U4S680rTse7nsTguQxzRs2vOyoaXm\nFdf7XQ03btd15Z4yJlEfs9/4ohgafMs49PMkACqyX45/4WBygO0QwMGVIUnKNFBt\n/I+0T2SkWFa2JdcRCSTObb7tesoeTIPgI9UcrMvNOG3gxGpB/H5/s7jTV0AOoDgM\nhOxieGgyTsZ3oP0k6bc47FJ4nE+vifAluyeXioB5JaN2kvm8eqfzC05zSF40V9GA\nzElVDbsBPR/2CE6CMyR+eqip4gDSZ6mnZYPeBecEXU4Xu+RAgqYxjKosfxOpMZsN\n+2BSm5QSRLhHacPQTnoQxujnGuUzh5TdAbWqmS0cKEZJ+CACmVLyOphdRoeEQCqQ\n8DYAyOtq2S4+hAJW+2Xq4NCdvmjm99r2RFkibSlLtqctj1JyzUC6huUiQXx9KZ8n\nFA0TsFHG\n"
        ));

        [Fact(DisplayName = "Test XmlSignatureVerification can load NemId sample")]
        public void XmlSignatureVerificationNemIdLoadTest()
        {
            var testxml = EmbeddedResourceExtractor.GetString<BankIdSeSignatureVerificationTests>("MobileLife.OBCO.DataTests.Signicat.Samples.nemid_opensign_pocesII.xml");
            var verifier = new XmlSignatureVerification(testxml);
            Assert.True(verifier.ValidReferences.Count > 0);
            Assert.True(verifier.TryValidateSignature(SystemTestNemIdRootCertificate, DateTime.Parse("2016-01-01 02:10:31.296761+00")));
        }

        [Fact(DisplayName = "Test XmlSignatureVerification can load BankId SE sample")]
        public void XmlSignatureVerificationBankIdSeTest()
        {
            var testxml = EmbeddedResourceExtractor.GetString<BankIdSeSignatureVerificationTests>("MobileLife.OBCO.DataTests.Signicat.Samples.bankid-se_signicat_sample.xml");
            var verifier = new XmlSignatureVerification(testxml);
            Assert.True(verifier.ValidReferences.Count > 0);
            Assert.True(verifier.ValidateSignature(SystemTestBankIdSeRootCertificate, DateTime.Parse("2017-02-01 02:10:31.296761+00")));
        }

        [Fact(DisplayName = "Test signature validation from Signicat")]
        public void ValidateSignicatSignatureTest()
        {
            var testxml = EmbeddedResourceExtractor.GetString<BankIdSeSignatureVerificationTests>("MobileLife.OBCO.DataTests.Signicat.Samples.bankid-se_signicat_sample.xml");
            var verifier = new BankIdSeSignatureVerification(testxml);
            Assert.True(verifier.ValidateSignature(DateTimeOffset.Parse("2017-02-01 02:10:31.296761+00"), true));
            var jsonBase64Payload = verifier.UserNonVisibleData;
            var payload = new SignicatPayload(jsonBase64Payload);
            Assert.True(payload.ValidateAttachment(0, EmbeddedResourceExtractor.GetStream<BankIdSeSignatureVerificationTests>("MobileLife.OBCO.DataTests.Signicat.Samples.bankid-se_signicat_sample.pdf")));
        }

    }
}