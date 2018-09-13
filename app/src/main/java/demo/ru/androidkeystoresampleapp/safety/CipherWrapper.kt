package demo.ru.androidkeystoresampleapp.safety

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
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
     * Encrypt data with a Secret Key and returns an encrypted data with an init vector.
     *
     * [data] - a ByteArray representation of plain data
     * [secretKey] - a Secret Key for the encryption
     */
    fun encrypt(data: ByteArray, secretKey: SecretKey): ByteArray {

        val initVector = createInitVectorForEncryption()
        val initVectorParameterSpec = IvParameterSpec(initVector)

        // Get a cipher instance for the encryption
        val cipher: Cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, initVectorParameterSpec)

        // Encrypt data and concat it with init vector
        val encryptedData = cipher.doFinal(data)
        return initVector.plus(encryptedData)
    }

    /**
     * Decrypt data with a Secret Key and returns a decrypted data as a ByteArray
     *
     * [data] - a ByteArray, that contains both init vector and encrypted data
     * [secretKey] - a Secret Key for the decryption
     */
    fun decrypt(data: ByteArray, secretKey: SecretKey): ByteArray {

        // Get an init vector from the beginning of the encrypted ByteArray
        val initVector = data.copyOfRange(0, IV_LENGTH)
        val initVectorParameterSpec = IvParameterSpec(initVector)

        // Get a Cipher instance for decryption and init it with a Secret Key and an init vector
        val cipher: Cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, initVectorParameterSpec)

        // Get an encrypted data and decrypt it
        val encryptedData = data.copyOfRange(fromIndex = IV_LENGTH, toIndex = data.size)
        return cipher.doFinal(encryptedData)
    }

    /**
     * Encrypt and copy data from the [inputStream] to the [outputStream].
     *
     * [inputStream] - an input stream that represents source "plain" data
     * [outputStream] - an output stream in which encrypted data will be written
     * [secretKey] - a Secret Key for the encryption
     */
    fun encryptStream(
        inputStream: InputStream,
        outputStream: OutputStream,
        secretKey: SecretKey
    ) {

        val initVector = createInitVectorForEncryption()
        val initVectorParameterSpec = IvParameterSpec(initVector)

        // Get a cipher instance for the encryption
        val cipher: Cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, initVectorParameterSpec)

        // Decorate an outputStream with a CipherOutputStream
        val cipherOutputStream = CipherOutputStream(outputStream, cipher)

        try {
            // Write init vector to the outputStream at first and then encrypt and copy main data
            outputStream.write(initVector)
            inputStream.copyTo(cipherOutputStream)

        } catch (e: IOException) {
            throw IOException("Error while encrypt input stream $e", e)

        } finally {
            inputStream.close()
            outputStream.close()
        }
    }

    /**
     * Decrypt and copy data from the [inputStream] to the [outputStream].
     *
     * [inputStream] - an input stream that represents encrypted data
     * [outputStream] - an output stream in which decrypted data will be written
     * [secretKey] - a Secret Key for the decryption
     */
    fun decryptStream(
        inputStream: InputStream,
        outputStream: OutputStream,
        secretKey: SecretKey
    ) {
        val initVector = ByteArray(IV_LENGTH)

        try {
            // Read the first bytes for the init vector
            inputStream.read(initVector)
            val initVectorParameterSpec = IvParameterSpec(initVector)

            // Get a Cipher instance for decryption
            val cipher: Cipher = Cipher.getInstance(AES_TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, initVectorParameterSpec)

            // Decorate an inputStream with a CipherInputStream
            val cipherInputStream = CipherInputStream(inputStream, cipher)

            // Decrypt and copy data
            cipherInputStream.copyTo(outputStream)

        } catch (e: IOException) {
            throw IOException("Error while decrypt input stream $e", e)

        } finally {
            inputStream.close()
            outputStream.close()
        }
    }

    /**
     * Create init vector that required for encryption with AES algorithm
     */
    private fun createInitVectorForEncryption(): ByteArray {
        val initVector = ByteArray(IV_LENGTH)
        SecureRandom().nextBytes(initVector)
        return initVector
    }
}