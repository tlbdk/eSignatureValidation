using System;
using System.IO;
using System.Reflection;
using System.Text;

namespace eSignatureValidation.Tests.Common
{
    public class EmbeddedResourceExtractor
    {
        public static Stream GetStream<T>(string resourceName)
        {
            var assembly = typeof(T).GetTypeInfo().Assembly;
            var stream = assembly.GetManifestResourceStream(resourceName);
            if (stream == null)
            {
                throw new Exception("Did not find resource");
            }

            return stream;
        }

        public static string GetString<T>(string resourceName, Encoding encoding = null)
        {
            using (var stream = GetStream<T>(resourceName))
            using (var reader = new StreamReader(stream, encoding ?? Encoding.UTF8))
            {
                return reader.ReadToEnd();
            }
        }

        public static byte[] GetBytes<T>(string resourceName)
        {
            using (var stream = GetStream<T>(resourceName))
            using (var memoryStream = new MemoryStream())
            {
                stream.CopyTo(memoryStream);
                return memoryStream.ToArray();
            }
        }

        public static string[] GetNames<T>()
        {
            return typeof(T).GetTypeInfo().Assembly.GetManifestResourceNames();
        }
    }
}