using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.XmlDocumentXPathExtensions;

namespace eSignatureValidation
{
    public class XmlSignatureVerification
    {
        private readonly XmlNode _signatureNode;
        private readonly XmlNamespaceManager _xmlNamespaces;

        public List<XmlElement> ValidReferences { get; set; }

        public XmlSignatureVerification(string xml) : this(new MemoryStream(Encoding.UTF8.GetBytes(xml)))
        {
        }

        public XmlSignatureVerification(Stream xmlStream)
        {
            var reader = XmlReader.Create(xmlStream, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                MaxCharactersFromEntities = 30,
                //XmlResolver = null
            });
            var doc = new XmlDocument { PreserveWhitespace = true };
            doc.Load(reader);

            _xmlNamespaces = new XmlNamespaceManager(doc.NameTable);
            _xmlNamespaces.AddNamespace("openoces", "http://www.openoces.org/2006/07/signature#");
            _xmlNamespaces.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

            var rootElement = doc?.DocumentElement;

            if (rootElement?.NamespaceURI == "http://www.openoces.org/2006/07/signature#" && rootElement.LocalName == "signature") // Format used by NemId
            {
                _signatureNode = doc.SelectSingleNode("//openoces:signature/ds:Signature[1]",  _xmlNamespaces);

            } else if (rootElement?.Name == "Signature") // Format used by BankId SE
            {
                _signatureNode = doc.SelectSingleNode("//ds:Signature[1]", _xmlNamespaces);
            }
            else
            {
                throw new XmlSignatureVerificationException("Failed to find signature section in document");
            }

            var references = GetValidReferences(_signatureNode);
            if (references == null || references.Count == 0)
            {
                throw new XmlSignatureVerificationException("Found no references in the document");
            }

            ValidReferences = references;
        }

        public bool ValidateSignature(X509Certificate2 rootCertificate, DateTimeOffset? signatureTime = null)
        {
            if (signatureTime != null && signatureTime > DateTimeOffset.Now)
            {
                throw new XmlSignatureVerificationException("signatureTime is in the future");
            }

            // Extract signature value for SignedInfo
            var nav = _signatureNode.CreateNavigator();
            nav.MoveToFollowing("SignatureValue", "http://www.w3.org/2000/09/xmldsig#");
            var signatureValue = Regex.Replace(nav.InnerXml.Trim(), @"\s", "");
            var sigVal = Convert.FromBase64String(signatureValue);

            // Extract SignedInfo and hash
            var signedInfo = _signatureNode.SelectSingleNode("//ds:Signature/ds:SignedInfo[1]", _xmlNamespaces);
            var ns = RetrieveNameSpaces((XmlElement)signedInfo);
            InsertNamespacesIntoElement(ns, (XmlElement)signedInfo);
            var signedInfoStream = CanonicalizeNode(signedInfo);
            var sha256 = SHA256.Create();
            var hashedSignedInfo = sha256.ComputeHash(signedInfoStream);

            // Extract all certificates
            var certificateNodes = _signatureNode.SelectNodes("//ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate", _xmlNamespaces);
            if (certificateNodes == null || certificateNodes.Count == 0)
            {
                throw new XmlSignatureVerificationException("Did not find any X509Certificate in the X509Data section of the signature");
            }
            var certificates = new List<X509Certificate2>();
            foreach (XmlNode certificateNode in certificateNodes)
            {
                var certificateBas64 = Regex.Replace(certificateNode.InnerXml.Trim(), @"\s", "");
                var certificate = new X509Certificate2(Convert.FromBase64String(certificateBas64));
                certificates.Add(certificate);
            }

            // Validate signature for SignedInfo
            var csp = (RSACryptoServiceProvider) CryptoUtils.GetSignerCertificate(rootCertificate, certificates, signatureTime).PublicKey.Key;
            return csp.VerifyHash(hashedSignedInfo, CryptoConfig.MapNameToOID("SHA256"), sigVal);
        }

        public bool TryValidateSignature(X509Certificate2 rootCertificate, DateTimeOffset? signatureTime = null)
        {
            try
            {
                return ValidateSignature(rootCertificate, signatureTime);
            }
            catch(Exception)
            {
                return false;
            }
        }

        private List<XmlElement> GetValidReferences(XmlNode doc)
        {
            var messageReferences = doc.SelectNodes("//ds:Signature/ds:SignedInfo/ds:Reference", _xmlNamespaces);
            if (messageReferences == null || messageReferences.Count == 0)
            {
                return null;
            }

            var results = new List<XmlElement>();
            foreach (XmlNode node in messageReferences)
            {
                var referencedNode = GetValidReference(doc, node);
                if (referencedNode != null)
                {
                    results.Add(referencedNode);

                }
                else
                {
                    return null;
                }
            }
            return results;
        }

        private static XmlElement GetValidReference(XmlNode doc, XmlNode node)
        {
            var elementNav = node.CreateNavigator();
            var elementId = elementNav.GetAttribute("URI", "");
            if (elementId.StartsWith("#"))
            {
                elementId = elementId.Substring(1);
            }

            var referencedNode = RetrieveElementByAttribute(doc, "Id", elementId);
            InsertNamespacesIntoElement(RetrieveNameSpaces((XmlElement)referencedNode.ParentNode), referencedNode);

            var canonicalizedNodeStream = CanonicalizeNode(referencedNode);

            elementNav.MoveToFollowing("DigestMethod", "http://www.w3.org/2000/09/xmldsig#");
            var hashAlg = (HashAlgorithm)CryptoConfig.CreateFromName(elementNav.GetAttribute("Algorithm", ""));
            var hashedNode = hashAlg.ComputeHash(canonicalizedNodeStream);

            elementNav.MoveToFollowing("DigestValue", "http://www.w3.org/2000/09/xmldsig#");
            var digestValue = Convert.FromBase64String(elementNav.InnerXml);

            if (hashedNode.SequenceEqual(digestValue))
            {
                return referencedNode;
            }
            else
            {
                return null;
            }
        }

        private static Hashtable RetrieveNameSpaces(XmlNode xEle)
        {
            var foundNamespaces = new Hashtable();
            var currentNode = xEle;

            while (currentNode != null)
            {
                if (currentNode.NodeType == XmlNodeType.Element && !string.IsNullOrEmpty(currentNode.Prefix))
                {
                    if (!foundNamespaces.ContainsKey("xmlns:" + currentNode.Prefix))
                    {
                        foundNamespaces.Add("xmlns:" + currentNode.Prefix, currentNode.NamespaceURI);
                    }
                }

                if (currentNode.Attributes != null && currentNode.Attributes.Count > 0)
                {
                    for (var i = 0; i < currentNode.Attributes.Count; i++)
                    {
                        if (currentNode.Attributes[i].Prefix.Equals("xmlns") || currentNode.Attributes[i].Name.Equals("xmlns"))
                        {
                            if (!foundNamespaces.ContainsKey(currentNode.Attributes[i].Name))
                            {
                                foundNamespaces.Add(currentNode.Attributes[i].Name, currentNode.Attributes[i].Value);
                            }
                        }
                    }
                }
                currentNode = currentNode.ParentNode;
            }
            return foundNamespaces;
        }

        private static void InsertNamespacesIntoElement(Hashtable namespacesHash, XmlElement node)
        {
            var nav = node.CreateNavigator();
            /*if (string.IsNullOrEmpty(nav.Prefix) && string.IsNullOrEmpty(nav.GetAttribute("xmlns", "")))
            {
                nav.CreateAttribute("", "xmlns", "", nav.NamespaceURI);
            } */
            foreach (DictionaryEntry namespacePair in namespacesHash)
            {
                var attrName = ((string)namespacePair.Key).Split(':');
                if (attrName.Length > 1 && !node.HasAttribute(attrName[0] + ":" + attrName[1]))
                {
                    nav.CreateAttribute(attrName[0], attrName[1], "", (string)namespacePair.Value);
                }
            }
        }

        private static Stream CanonicalizeNode(XmlNode node)
        {
            var reader = new XmlNodeReader(node);
            Stream stream = new MemoryStream();
            XmlWriter writer = new XmlTextWriter(stream, Encoding.UTF8);

            writer.WriteNode(reader, false);
            writer.Flush();

            stream.Position = 0;
            var transform = new XmlDsigC14NTransform();
            transform.LoadInput(stream);
            return (Stream)transform.GetOutput();
        }

        private static XmlElement RetrieveElementByAttribute(XmlNode xDoc, string attributeName, string attributeValue)
        {
            XmlElement foundElement = null;
            foreach (XmlNode node in xDoc)
            {
                if (node.HasChildNodes)
                {
                    foundElement = RetrieveElementByAttribute(node, attributeName, attributeValue);
                }
                if (foundElement == null && node.Attributes != null && node.Attributes[attributeName] != null && node.Attributes[attributeName].Value.ToLower().Equals(attributeValue.ToLower()))
                {
                    foundElement = (XmlElement)node;
                    break;
                }
                if (foundElement != null)
                {
                    break;
                }
            }
            return foundElement;
        }
    }

    [Serializable]
    public class XmlSignatureVerificationException : Exception
    {
        public XmlSignatureVerificationException() { }
        public XmlSignatureVerificationException(string message) : base(message) { }
        public XmlSignatureVerificationException(string message, Exception inner) : base(message, inner) { }
    }
}