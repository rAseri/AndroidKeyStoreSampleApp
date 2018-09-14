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
 * for the input data using a [Cipher] class.
 */
class CipherWrapper {

    companion object {

        /**
         * The length of an initialization vector (IV)
         */
        private const val IV_LENGTH = 16

        /**
         * The transformation represents the algorithm, that will be used for encryption or decryption,
         * in format of: ”Algorithm/Mode/Padding”
         */
        private const val AES_TRANSFORMATION = "AES/CBC/PKCS7Padding"
        private const val RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding"
    }

    /**
     * Wrap (encrypt) Secret Key with a Master Public Key.
     * Wrapped Secret Key can be securely stored in the private Storage.
     */
    fun wrapSecretKey(keyToBeWrapped: SecretKey, keyToWrapWith: PublicKey): ByteArray {
        val cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        cipher.init(Cipher.WRAP_MODE, keyToWrapWith)

        return cipher.wrap(keyToBeWrapped)
    }

    /**
     * Unwrap (decrypt) Secret Key with a Master Private Key
     */
    fun unWrapSecretKey(keyToBeUnWrapped: ByteArray, keyToUnWrapWith: PrivateKey): SecretKey {
        val cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        cipher.init(Cipher.UNWRAP_MODE, keyToUnWrapWith)

        return cipher.unwrap(keyToBeUnWrapped, Algorithm.AES, Cipher.SECRET_KEY) as SecretKey
    }

    /**
     * Encrypt data with a Secret Key and returns both the encrypted data
     * and an initialization vector (IV) in the same ByteArray.
     *
     * [data] - the ByteArray representation of plain data
     * [secretKey] - the Secret Key for encryption
     */
    fun encrypt(data: ByteArray, secretKey: SecretKey): ByteArray {

        val initVector = generateInitVectorForEncryption()
        val initVectorParameterSpec = IvParameterSpec(initVector)

        // Get a Cipher instance for encryption
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, initVectorParameterSpec)

        // Encrypt data and concat it with the initialization vector
        val encryptedData = cipher.doFinal(data)
        return initVector + encryptedData
    }

    /**
     * Decrypt data with a Secret Key and initialization vector (IV)
     * that is contained in the [data] ByteArray.
     *
     * [data] - the ByteArray that contains both initialization vector and encrypted data
     * [secretKey] - the Secret Key for decryption
     */
    fun decrypt(data: ByteArray, secretKey: SecretKey): ByteArray {

        // Get an initialization vector from the beginning of the ByteArray
        val initVector = data.copyOfRange(0, IV_LENGTH)
        val initVectorParameterSpec = IvParameterSpec(initVector)

        // Get a Cipher instance for decryption
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, initVectorParameterSpec)

        // Get an encrypted data and decrypt it
        val encryptedData = data.copyOfRange(fromIndex = IV_LENGTH, toIndex = data.size)
        return cipher.doFinal(encryptedData)
    }

    /**
     * Encrypt and copy data from the [inputStream] to the [outputStream].
     *
     * [inputStream] - the input stream that represents source "plain" data
     * [outputStream] - the output stream in which encrypted data will be written
     * [secretKey] - the Secret Key for encryption
     */
    fun encryptInputStream(
        inputStream: InputStream,
        outputStream: OutputStream,
        secretKey: SecretKey
    ) {

        val initVector = generateInitVectorForEncryption()
        val initVectorParameterSpec = IvParameterSpec(initVector)

        // Get a cipher instance for encryption
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, initVectorParameterSpec)

        // Decorate an outputStream with a CipherOutputStream for encryption
        val cipherOutputStream = CipherOutputStream(outputStream, cipher)

        try {
            // Write initialization vector to the outputStream at first
            // and then encrypt and copy main data
            outputStream.write(initVector)
            inputStream.copyTo(cipherOutputStream)

        } catch (e: IOException) {
            throw IOException("Error while encrypt and copy data $e", e)

        } finally {
            inputStream.close()
            cipherOutputStream.close()
        }
    }

    /**
     * Decrypt and copy data from the [inputStream] to the [outputStream].
     *
     * [inputStream] - the input stream that represents encrypted data
     * [outputStream] - the output stream in which decrypted data will be written
     * [secretKey] - the Secret Key for decryption
     */
    fun decryptInputStream(
        inputStream: InputStream,
        outputStream: OutputStream,
        secretKey: SecretKey
    ) {
        val initVector = ByteArray(IV_LENGTH)
        var cipherInputStream: CipherInputStream? = null

        try {
            // Read the initialization vector from the first bytes of the inputStream
            inputStream.read(initVector)
            val initVectorParameterSpec = IvParameterSpec(initVector)

            // Get a Cipher instance for decryption
            val cipher = Cipher.getInstance(AES_TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, initVectorParameterSpec)

            // Decorate an inputStream with a CipherInputStream for decryption
            cipherInputStream = CipherInputStream(inputStream, cipher)

            // Decrypt and copy data
            cipherInputStream.copyTo(outputStream)

        } catch (e: IOException) {
            throw IOException("Error while decrypt input stream $e", e)

        } finally {
            cipherInputStream?.close() ?: inputStream.close()
            outputStream.close()
        }
    }

    /**
     * Generate initialization vector (IV) that required for encryption with AES algorithm
     */
    private fun generateInitVectorForEncryption(): ByteArray {
        val initVector = ByteArray(IV_LENGTH)
        SecureRandom().nextBytes(initVector)
        return initVector
    }
}