using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace MobileLife.OBCO.Data.Signicat
{
    public class SignicatPayload
    {
        private readonly SHA256 sha256 = SHA256.Create();

        public Attachment[] Attachments { get; set; }

        public SignicatPayload(string base64Payload)
        {
            var jsonBytes = Convert.FromBase64String(base64Payload);
            var json = Encoding.UTF8.GetString(jsonBytes);
            JsonConvert.PopulateObject(json, this, new JsonSerializerSettings()
            {
                ContractResolver = new CamelCasePropertyNamesContractResolver()
            });
        }

        public bool ValidateAttachment(int index, Stream stream)
        {
            var signicatHash = Convert.FromBase64String(this.Attachments[index].DigestValue);
            var pdfHash = sha256.ComputeHash(stream);
            return signicatHash.SequenceEqual(pdfHash);
        }

        public bool ValidateAttachment(int index, byte[] bytes)
        {
            var signicatHash = Convert.FromBase64String(this.Attachments[index].DigestValue);
            var pdfHash = sha256.ComputeHash(bytes);
            return signicatHash.SequenceEqual(pdfHash);
        }


        public bool ValidateAttachment(int index, string path)
        {
            using (var file = File.Open(path, FileMode.Open))
            {
                return ValidateAttachment(index, file);
            }
        }
    }

    public class Attachment
    {
        public string DigestValue { get; set; }
        public string DocumentDescription { get; set; }
        public string MimeType { get; set; }
        public int SerialNumber { get; set; }
        public DigestMethod DigestMethod { get; set; }
        public string SecondaryDigestValue { get; set; }
        public DigestMethod SecondaryDigestMethod { get; set; }
    }

    public class DigestMethod
    {
        public String Algorithm { get; set; }
    }
}
