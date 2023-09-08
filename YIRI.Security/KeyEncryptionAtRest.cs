using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;

namespace YIRI.Security
{
    internal static class AesKeyingMaterial
    {
        internal static readonly byte[] Key = Convert.FromBase64String("68jgB2lhZ/UYr14aSzi4AKsaeiS2jQvcYIJDhhzwcws=");
        internal static readonly byte[] IV = Convert.FromBase64String("6VYIsDg5VDfRWR0KYCp5Dw==");
        internal const string KEY_NAME = "YIRI_AES";
    }

    public sealed class AesXmlEncryptor : IXmlEncryptor
    {
        public EncryptedXmlInfo Encrypt(XElement plaintextElement)
        {
            if (plaintextElement is null) throw new ArgumentNullException(nameof(plaintextElement));

            // <EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns="http://www.w3.org/2001/04/xmlenc#">
            //   ...
            // </EncryptedData>

            XElement encryptedElement;
            // Create an AesCryptoServiceProvider object
            // with the specified key and IV.
            using (Aes yiriAes = Aes.Create())
            {
                yiriAes.Key = AesKeyingMaterial.Key;
                yiriAes.IV = AesKeyingMaterial.IV;
                encryptedElement = EncryptElement(plaintextElement, yiriAes);
            }
            return new EncryptedXmlInfo(encryptedElement, typeof(AesXmlDecryptor));
        }

        private XElement EncryptElement(XElement plaintextElement, SymmetricAlgorithm keyObj)
        {
            if (keyObj is null) throw new ArgumentNullException(nameof(keyObj));
            // EncryptedXml works with XmlDocument, not XLinq. When we perform the conversion
            // we'll wrap the incoming element in a dummy <root /> element since encrypted XML
            // doesn't handle encrypting the root element all that well.
            var xmlDocument = new XmlDocument();
            xmlDocument.Load(new XElement("root", plaintextElement).CreateReader());
            var elementToEncrypt = (XmlElement)xmlDocument.DocumentElement!.FirstChild!;

            // Perform the encryption and update the document in-place.
            var encryptedXml = new EncryptedXml(xmlDocument);
            encryptedXml.AddKeyNameMapping(AesKeyingMaterial.KEY_NAME, keyObj);
            var encryptedData = encryptedXml.Encrypt(elementToEncrypt, AesKeyingMaterial.KEY_NAME);
            EncryptedXml.ReplaceElement(elementToEncrypt, encryptedData, content: false);

            // Strip the <root /> element back off and convert the XmlDocument to an XElement.
            return XElement.Load(xmlDocument.DocumentElement.FirstChild!.CreateNavigator()!.ReadSubtree());
        }

    }

    internal sealed class AesXmlDecryptor : IXmlDecryptor
    {
        /// <summary>
        /// Can decrypt the XML key data from an <see cref="Aes"/>.
        /// </summary>
        private class EncryptedXmlWithAesKeys : EncryptedXml
        {
            private readonly SymmetricAlgorithm? _keyObj;
            public EncryptedXmlWithAesKeys(XmlDocument document, SymmetricAlgorithm? keyObj)
                : base(document)
            {
                _keyObj = keyObj;
            }

            public override byte[] DecryptEncryptedKey(EncryptedKey encryptedKey)
            {
                if (_keyObj != null) return DecryptKey(encryptedKey.CipherData.CipherValue, _keyObj);
                return base.DecryptEncryptedKey(encryptedKey);
            }

        }

        public XElement Decrypt(XElement encryptedElement)
        {
            if (encryptedElement is null) throw new ArgumentNullException(nameof(encryptedElement));

            XmlDocument xmlDocument;
            using (Aes yiriAes = Aes.Create())
            {
                yiriAes.Key = AesKeyingMaterial.Key;
                yiriAes.IV = AesKeyingMaterial.IV;
                // <EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns="http://www.w3.org/2001/04/xmlenc#">
                //   ...
                // </EncryptedData>

                // EncryptedXml works with XmlDocument, not XLinq. When we perform the conversion
                // we'll wrap the incoming element in a dummy <root /> element since encrypted XML
                // doesn't handle encrypting the root element all that well.
                xmlDocument = new XmlDocument();
                xmlDocument.Load(new XElement("root", encryptedElement).CreateReader());

                // Perform the decryption and update the document in-place.
                var encryptedXml = new EncryptedXmlWithAesKeys(xmlDocument, yiriAes);

                encryptedXml.DecryptDocument();
            }

            // Strip the <root /> element back off and convert the XmlDocument to an XElement.
            return XElement.Load(xmlDocument.DocumentElement!.FirstChild!.CreateNavigator()!.ReadSubtree());
        }
    }

}
