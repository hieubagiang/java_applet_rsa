package RSAExample;

import javacard.framework.*;
import javacard.framework.OwnerPIN;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;
import javacard.security.AESKey;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.apdu.ExtendedLength;
import javacard.security.*;
import javacardx.crypto.*;
public class RSAExample extends Applet
{
	final static byte GET_FIRST_MESSAGE =(byte)0x00;
	final static byte GET_EXPORT_PUBLIC_MODULUS = (byte)0x20;
	final static byte GET_EXPORT_PUBLIC_EXPONENT = (byte)0x21;
	private RSAPublicKey rsaPubKey;
	private RSAPrivateKey rsaPrivKey;
	private Signature rsaSig;
	private short sigLen;
	private byte[] sig_buffer;
	
	
	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new RSAExample(bArray, bOffset, bLength);
	}
	
	private RSAExample(byte[] bArray, short bOffset, byte bLength) {
	
		createRSAKey();
		
		register();
	}
	public void createRSAKey(){
		sigLen = (short)(KeyBuilder.LENGTH_RSA_1024 /8);
		sig_buffer = new byte[sigLen];
		rsaSig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1,false);
		rsaPrivKey = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,(short)(8*sigLen),false);
		rsaPubKey =	(RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,(short)(8*sigLen), false);

		KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA,(short)(8*sigLen));
		keyPair.genKeyPair();
		rsaPrivKey = (RSAPrivateKey)keyPair.getPrivate();
		rsaPubKey = (RSAPublicKey)keyPair.getPublic();
	}
	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}

		byte[] buf = apdu.getBuffer();
		short byteRead = (short)(apdu.setIncomingAndReceive());
		short dataLen = (short)(buf[ISO7816.OFFSET_LC]&0xff);
				
		switch (buf[ISO7816.OFFSET_INS])
			{
			case (byte) GET_FIRST_MESSAGE:
				getFirstMessage(apdu);
				break;
			case (byte) GET_EXPORT_PUBLIC_MODULUS:
				exportPublicModulus(apdu);
				break;
			case (byte) GET_EXPORT_PUBLIC_EXPONENT:
				exportPublicExponent(apdu);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
	}
		
	private void getFirstMessage(APDU apdu) {
		final byte message[] = {'h','e','l','l','o',' ','f','r','o','m',' ','a','p','p','l','e','t'};
		byte buffer[] = apdu.getBuffer();
		Util.arrayCopyNonAtomic(message,(short)0,buffer,(short)0,(short)message.length);
		apdu.setOutgoingAndSend((short) 0, (short)message.length);
	}
	
	private void exportPublicModulus(APDU apdu) {
		byte buffer[] = apdu.getBuffer();
		short modulusExportLen = rsaPubKey.getModulus(buffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, (short) (modulusExportLen));
	}
	
	private void exportPublicExponent(APDU apdu) {
		byte buffer[] = apdu.getBuffer();
		short exponentExportLen = rsaPubKey.getExponent(buffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, (short) exponentExportLen);
	}
}
