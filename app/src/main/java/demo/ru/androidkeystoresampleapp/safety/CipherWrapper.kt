package demo.ru.androidkeystoresampleapp.safety

import java.security.Key
import javax.crypto.Cipher

/**
 * This class responsible for performing encryption and decryption using [Cipher]
 */
class CipherWrapper {

    companion object {
        private const val TRANSFORMATION_ASYMMETRIC = "RSA/ECB/PKCS1Padding"
    }

    fun encrypt(plainBytes: ByteArray, key: Key): ByteArray {
        val cipher: Cipher = Cipher.getInstance(TRANSFORMATION_ASYMMETRIC)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(plainBytes)
    }

    fun decrypt(encryptedBytes: ByteArray, key: Key): ByteArray {
        val cipher: Cipher = Cipher.getInstance(TRANSFORMATION_ASYMMETRIC)
        cipher.init(Cipher.DECRYPT_MODE, key)
        return cipher.doFinal(encryptedBytes)
    }
}