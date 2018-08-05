package demo.ru.androidkeystoresampleapp.safety

import android.content.Context
import android.util.Base64
import java.security.PublicKey
import javax.crypto.SecretKey

/**
 * This class is a simple Facade for secrets managing.
 * It responsible for performing encryption and decryption operations, initial key generation etc.
 */
class SecretManager(context: Context, private val storage: Storage) {

    companion object {
        private const val MASTER_KEY = "master.key"
    }

    private val cipherWrapper = CipherWrapper()
    private val keyStoreWrapper = KeyStoreWrapper(context)

    init {
        var masterKey = keyStoreWrapper.getAndroidKeyStoreAsymmetricKeyPair(MASTER_KEY)

        // NOTE: RSA Master Key may be null when user setup device protection with PIN code
        if (masterKey == null) {

            // Generate asymmetric RSA Master Key and save it to secure AndroidKeyStore
            masterKey = keyStoreWrapper.generateAndroidKeyStoreAsymmetricKey(MASTER_KEY)

            // Generate symmetric AES Secret Key, wrap it with Master Key and save it to local Storage
            generateAndSaveSecretKey(masterPublicKey = masterKey.public)

        } else if (storage.getWrappedSecretKey() == null) {

            // Generate symmetric AES Secret Key, wrap it with Master Key and save it to local Storage
            generateAndSaveSecretKey(masterPublicKey = masterKey.public)
        }
    }

    private fun generateAndSaveSecretKey(masterPublicKey: PublicKey) {

        // Generate AES symmetric Secret Key
        val secretKey = keyStoreWrapper.generateDefaultSymmetricKey()

        // Wrap Secret Key with RSA asymmetric Master Key
        val wrappedSecretKey = cipherWrapper.wrapKey(
            keyToBeWrapped = secretKey,
            keyToWrapWith = masterPublicKey
        )

        // Save Secret Key to local Storage
        storage.saveWrappedSecretKey(
            wrappedSecretKey = Base64.encodeToString(wrappedSecretKey, Base64.DEFAULT)
        )
    }

    /**
     * Encrypt String data and returns its Base64 representation
     *
     * [data] - data to be encrypted
     */
    fun encryptStringData(data: String): String {

        // Get AES symmetric Secret Key
        val secretKey = getSecretKey()

        // Encrypt data with AES symmetric Secret Key
        val encryptedData = cipherWrapper.encrypt(
            data = data.toByteArray(),
            secretKey = secretKey
        )

        return Base64.encodeToString(encryptedData, Base64.DEFAULT)
    }

    /**
     * Decrypt String data
     *
     * [data] - data to be decrypted, represented as Base64 String
     */
    fun decryptStringData(data: String): String {

        // Get AES symmetric Secret Key
        val secretKey = getSecretKey()

        // Decrypt data with AES symmetric Secret Key
        val decryptedData = cipherWrapper.decrypt(
            data = Base64.decode(data, Base64.DEFAULT),
            secretKey = secretKey
        )

        return String(decryptedData)
    }

    private fun getSecretKey(): SecretKey {

        // Get RSA asymmetric Master Key from AndroidKeyStore
        val masterKey = keyStoreWrapper.getAndroidKeyStoreAsymmetricKeyPair(MASTER_KEY)
                ?: throw IllegalStateException("There is no master key in AndroidKeyStore")

        // Get wrapped AES symmetric Secret Key from local Storage
        val wrappedSecretKey = storage.getWrappedSecretKey()
                ?: throw IllegalStateException("There is no encrypted secret key in local Storage")

        // Unwrap Secret Key with RSA Private Key
        return cipherWrapper.unWrapKeySecretKey(
            keyToBeUnWrapped = Base64.decode(wrappedSecretKey, Base64.DEFAULT),
            keyToUnWrapWith = masterKey.private
        )
    }
}