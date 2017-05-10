using System;
using System.Xml.Linq;
using eSignatureValidation.Tests.Common;
using Xunit;

namespace eSignatureValidation.Tests
{
    public class SignicatLtvSdoValidationTests
    {
        [Fact(DisplayName = "Extract NativeSdo and original document")]
        public void ExtractNativeSdoTest()
        {
            var testxml = EmbeddedResourceExtractor.GetString<NemidSignatureVerificationTests>("MobileLife.OBCO.DataTests.Signicat.Samples.signicat_bankid-se_sample.xml");
            var ltSdoXDoc = XDocument.Parse(testxml);

            XNamespace nsLtv = "https://id.signicat.com/definitions/xsd/LtvSdo-1.1";
            var nativeSdoBase64 = ltSdoXDoc.Root?
                .Element(nsLtv + "NativeSignature")?
                .Element(nsLtv + "NativeSdo")?
                .Value;

            var originalDocumentBase64 = ltSdoXDoc.Root?
                .Element(nsLtv + "NativeSignature")?
                .Element(nsLtv + "OriginalDocument")?
                .Value;

            var nativeSdoBytes = Convert.FromBase64String(nativeSdoBase64);
            //File.WriteAllBytes(@"C:\repos\git\OnboardingCustomers\MobileLife.OBCO.DataTests\Signicat\Samples\bankid-se_signicat_sample.xml", nativeSdoBytes);

            var originalDocument = Convert.FromBase64String(originalDocumentBase64);
            //File.WriteAllBytes(@"C:\repos\git\OnboardingCustomers\MobileLife.OBCO.DataTests\Signicat\Samples\bankid-se_signicat_sample.pdf", originalDocument);
        }
    }
}