using log4net;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Text;

namespace HPPSignatureVerificationCSharp
{
    public class ECDSASignature
    {

        private const string BOUNCY_CASTLE_SECURITY_PROVIDER = "BC";
        private const string ELLIPTICAL_CURVE_DIGITAL_SIGNATURE_ALG = "ECDSA";
        private const string SIGNATURE_ALG = "SHA384withECDSA";

        private static ILog LOGGER = LogManager.GetLogger(typeof(ECDSASignature));

        private const string INVALID_KEY_SPEC_OR_ALGORITH_MESSAGE = "InvalidKeySpec or Algorithm";
        private const string DECODER_ERROR_MESSAGE = "Decoding Failure";
        private const string SIGNATURE_ERROR_MESSAGE = "Invalid Key or Signature";

        private ECDSASignature() { }

        public static bool IsValid(string message, AsymmetricKeyParameter publicKey, string signature)
        {
            bool isValidSignature = false;
            try
            {
                var sig = SignerUtilities.GetSigner(SIGNATURE_ALG);
                sig.Init(false, publicKey);
                sig.BlockUpdate(Encoding.ASCII.GetBytes(message), 0, message.Length);
                isValidSignature = sig.VerifySignature(Hex.Decode(signature));
            }
            catch (InvalidKeyException ke)
            {
                LOGGER.Error(SIGNATURE_ERROR_MESSAGE, ke);
                isValidSignature = false;
            }
            catch (SignatureException se)
            {
                LOGGER.Error(SIGNATURE_ERROR_MESSAGE, se);
                isValidSignature = false;
            }
            catch (Exception de)
            {
                LOGGER.Error(DECODER_ERROR_MESSAGE, de);
                isValidSignature = false;
            }
            return isValidSignature;
        }

        public static AsymmetricKeyParameter ConvertPublicKey(string publicKey)
        {
            try
            {
                return PublicKeyFactory.CreateKey(Hex.Decode(publicKey));
            }
            catch (Exception de)
            {
                LOGGER.Error(DECODER_ERROR_MESSAGE, de);
                throw new InvalidOperationException(DECODER_ERROR_MESSAGE, de);
            }
        }
    }
}
