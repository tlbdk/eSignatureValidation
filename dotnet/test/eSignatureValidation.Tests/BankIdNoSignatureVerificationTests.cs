using System;
using System.Security.Cryptography.X509Certificates;
using eSignatureValidation.Tests.Common;
using Xunit;

namespace eSignatureValidation.Tests
{
    public class BankIdNoSignatureVerificationTests
    {
        [Fact(DisplayName = "Test XmlSignatureVerification can load NemId sample")]
        public void BankIdNoTestSignatureVerificationTest()
        {
            var testxml = EmbeddedResourceExtractor.GetString<BankIdNoSignatureVerificationTests>("MobileLife.OBCO.DataTests.Signicat.Samples.bankid-no_signicat_sample.xml");
            var verifier = new BankIdNoSignatureVerification(testxml);
        }
    }
}