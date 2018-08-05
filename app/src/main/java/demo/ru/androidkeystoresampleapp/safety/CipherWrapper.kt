package demo.ru.androidkeystoresampleapp.safety

import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

/**
 * This class responsible for performing all `transformation`operations using [Cipher] class.
 */
class CipherWrapper {

    companion object {
        private const val TRANSFORMATION_SYMMETRIC = "AES/CBC/PKCS7Padding"
        private const val TRANSFORMATION_ASYMMETRIC = "RSA/ECB/PKCS1Padding"

        private const val AES_ALGORITHM = "AES"

        private const val IV_LENGTH = 16
    }

    /**
     * Wrap (encrypt) AES symmetric Secret Key with the RSA Public Key
     */
    fun wrapKey(keyToBeWrapped: SecretKey, keyToWrapWith: PublicKey): ByteArray {
        val cipher: Cipher = Cipher.getInstance(TRANSFORMATION_ASYMMETRIC)
        cipher.init(Cipher.WRAP_MODE, keyToWrapWith)

        return cipher.wrap(keyToBeWrapped)
    }

    /**
     * Unwrap (decrypt) AES symmetric Secret Key with the RSA Private Key
     */
    fun unWrapKeySecretKey(keyToBeUnWrapped: ByteArray, keyToUnWrapWith: PrivateKey): SecretKey {
        val cipher: Cipher = Cipher.getInstance(TRANSFORMATION_ASYMMETRIC)
        cipher.init(Cipher.UNWRAP_MODE, keyToUnWrapWith)

        return cipher.unwrap(keyToBeUnWrapped, AES_ALGORITHM, Cipher.SECRET_KEY) as SecretKey
    }

    /**
     * Encrypt data with AES symmetric Secret Key and returns encrypted data along with init vector
     *
     * [data] - ByteArray representation of plain data
     */
    fun encrypt(data: ByteArray, secretKey: SecretKey): ByteArray {

        // Create init vector that required for encryption with AES algorithm
        val initVector = ByteArray(IV_LENGTH)
        SecureRandom().nextBytes(initVector)
        val initVectorParameterSpec = IvParameterSpec(initVector)

        // Get cipher instance for encryption and init it with Secret Key and init vector
        val cipher: Cipher = Cipher.getInstance(TRANSFORMATION_SYMMETRIC)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, initVectorParameterSpec)

        // Encrypt data and concat it with init vector
        val encryptedData = cipher.doFinal(data)
        return initVector.plus(encryptedData)
    }

    /**
     * Decrypt data with AES symmetric Secret Key and returns decrypted data as ByteArray
     *
     * [data] - ByteArray, that contains both init vector and encrypted data
     */
    fun decrypt(data: ByteArray, secretKey: SecretKey): ByteArray {

        // Get init vector from the beginning of the encrypted array
        // and create IvParameterSpec instance
        val initVectorParameterSpec = IvParameterSpec(data, 0, IV_LENGTH)

        // Get cipher instance for decryption and init it with `secretKey` and `init vector`
        val cipher: Cipher = Cipher.getInstance(TRANSFORMATION_SYMMETRIC)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, initVectorParameterSpec)

        // Get `encrypted data` part without init vector
        val encryptedData = data.copyOfRange(
            fromIndex = IV_LENGTH,
            toIndex = data.size
        )

        return cipher.doFinal(encryptedData)
    }
}