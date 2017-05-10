using System;
using System.Linq;
using eSignatureValidation.Tests.Common;
using MobileLife.OBCO.Data;
using MobileLife.OBCO.Data.Common;
using MobileLife.OBCO.Data.Signicat;
using Xunit;

namespace eSignatureValidation.Tests
{
    public class NemidSignatureVerificationTests
    {
        [Fact(DisplayName = "Test signature validation with expired certificate that was valid at signing time")]
        public void ValidateNemIdSampleSignatureTest()
        {
            var testxml = EmbeddedResourceExtractor.GetString<NemidSignatureVerificationTests>("MobileLife.OBCO.DataTests.Signicat.Samples.nemid_opensign_pocesII.xml");
            var verifier = new NemidSignatureVerification(testxml);
            Assert.True(verifier.TryValidateSignature(DateTime.Parse("2016-01-01 02:10:31.296761+00"), true));            
        }

        [Fact(DisplayName = "Test signature validation with expired certificate outside signing time")]
        public void ValidateNemIdSampleSignatureOutsideSignedDateTest()
        {
            var testxml = EmbeddedResourceExtractor.GetString<NemidSignatureVerificationTests>("MobileLife.OBCO.DataTests.Signicat.Samples.nemid_opensign_pocesII.xml");
            var verifier = new NemidSignatureVerification(testxml);
            Assert.False(verifier.TryValidateSignature(DateTime.Parse("2018-01-01 02:10:31.296761+00"), true));
        }

        [Fact(DisplayName = "Test signature validation from Signicat")]
        public void ValidateSignicatSignatureTest()
        {
            var testxml = EmbeddedResourceExtractor.GetString<NemidSignatureVerificationTests>("MobileLife.OBCO.DataTests.Signicat.Samples.nemid_signicat_sample.xml");
            var verifier = new NemidSignatureVerification(testxml);
            var jsonBase64Payload = verifier.SignatureProperties
                .Where(p => p.Name == "signicat")
                .Select(p => p.Value)
                .SingleOrDefault();

            Assert.True(verifier.ValidateSignature(DateTimeOffset.Parse("2016-09-01 02:10:31.296761+00"), true));

            var payload = new SignicatPayload(jsonBase64Payload);
            Assert.True(payload.ValidateAttachment(0, EmbeddedResourceExtractor.GetStream<NemidSignatureVerificationTests>("MobileLife.OBCO.DataTests.Signicat.Samples.nemid_signicat_sample.pdf")));
        }
       
        [Fact(DisplayName = "Test signature validation from Signicat outside signer validaity")]
        public void ValidateSignicatSignatureOutsideValidityTest()
        {
            var testxml = EmbeddedResourceExtractor.GetString<NemidSignatureVerificationTests>("MobileLife.OBCO.DataTests.Signicat.Samples.nemid_signicat_sample.xml");
            var verifier = new NemidSignatureVerification(testxml);
            Assert.False(verifier.TryValidateSignature(DateTime.Parse("2016-01-01 02:10:31.296761+00"), true));
        }
    }
}