package demo.ru.androidkeystoresampleapp.safety

import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

/**
 * This class responsible for performing all encryption/decryption operations
 * using a [Cipher] class.
 */
class CipherWrapper {

    companion object {
        private const val IV_LENGTH = 16

        /**
         * The transformation represents the algorithm, that will be used for encryption or decryption,
         * in format of: ”Algorithm/Mode/Padding”
         */
        const val AES_TRANSFORMATION = "AES/CBC/PKCS7Padding"
        const val RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding"
    }

    /**
     * Wrap (encrypt) Secret Key with a Master Public Key
     */
    fun wrapSecretKey(keyToBeWrapped: SecretKey, keyToWrapWith: PublicKey): ByteArray {
        val cipher: Cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        cipher.init(Cipher.WRAP_MODE, keyToWrapWith)

        return cipher.wrap(keyToBeWrapped)
    }

    /**
     * Unwrap (decrypt) Secret Key with a Master Private Key
     */
    fun unWrapSecretKey(keyToBeUnWrapped: ByteArray, keyToUnWrapWith: PrivateKey): SecretKey {
        val cipher: Cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        cipher.init(Cipher.UNWRAP_MODE, keyToUnWrapWith)

        return cipher.unwrap(keyToBeUnWrapped, Algorithm.AES, Cipher.SECRET_KEY) as SecretKey
    }

    /**
     * Encrypt a data with a Secret Key and returns an encrypted data with an init vector.
     * The init vector is required during decryption with AES algorithm.
     *
     * [data] - ByteArray representation of plain data
     */
    fun encrypt(data: ByteArray, secretKey: SecretKey): ByteArray {

        // Create init vector that required for encryption with AES algorithm
        val initVector = ByteArray(IV_LENGTH)
        SecureRandom().nextBytes(initVector)
        val initVectorParameterSpec = IvParameterSpec(initVector)

        // Get a cipher instance for encryption and init it with a Secret Key and an init vector
        val cipher: Cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, initVectorParameterSpec)

        // Encrypt data and concat it with init vector
        val encryptedData = cipher.doFinal(data)
        return initVector.plus(encryptedData)
    }

    /**
     * Decrypt a data with a Secret Key and returns a decrypted data as a ByteArray
     *
     * The [data] contains both an init vector and an encrypted data.
     * The init vector is required during decryption with AES algorithm.
     *
     * [data] - ByteArray, that contains both init vector and encrypted data
     */
    fun decrypt(data: ByteArray, secretKey: SecretKey): ByteArray {

        // Get an init vector from the beginning of the encrypted ByteArray
        // and create an IvParameterSpec instance
        val initVectorParameterSpec = IvParameterSpec(data, 0, IV_LENGTH)

        // Get a Cipher instance for decryption and init it with a Secret Key and an init vector
        val cipher: Cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, initVectorParameterSpec)

        // Get an encrypted data without an init vector and decrypt it
        val encryptedData = data.copyOfRange(fromIndex = IV_LENGTH, toIndex = data.size)
        return cipher.doFinal(encryptedData)
    }
}