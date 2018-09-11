package demo.ru.androidkeystoresampleapp.safety

import android.content.Context
import android.util.Base64
import java.security.PublicKey
import javax.crypto.SecretKey

/**
 * This class is a simple Facade for the app secrets managing.
 *
 * It is responsible for performing encryption and decryption operations,
 * initial keys generation etc.
 */
class SecretManager(context: Context, private val storage: Storage) {

    companion object {
        private const val TEST_PASSPHRASE = "4423"
        private val TEST_SALT = byteArrayOf(1, 2, 3)
    }

    private val cipherWrapper = CipherWrapper()
    private val keyStoreWrapper = KeysManager(context)

    init {
        var masterKey = keyStoreWrapper.getAndroidKeyStoreAsymmetricKeyPair()

        // NOTE: RSA Master Key may be null when a user is setting or changing device protection mechanism
        if (masterKey == null) {

            // Generate asymmetric RSA Master Key and save it to secure AndroidKeystore
            masterKey = keyStoreWrapper.generateAndroidKeyStoreAsymmetricKey()

            // Generate Secret Key, wrap (encrypt) it with Master Key and save it to the local Storage
            generateAndSaveSecretKey(masterPublicKey = masterKey.public)

        } else if (storage.getWrappedSecretKey() == null) {

            // Generate Secret Key, wrap (encrypt) it with Master Key and save it to the local Storage
            generateAndSaveSecretKey(masterPublicKey = masterKey.public)
        }
    }

    private fun generateAndSaveSecretKey(masterPublicKey: PublicKey) {

        // Generate a Secret Key
        val secretKey = keyStoreWrapper.generateSecretKeyForPrivateData(
            passphrase = TEST_PASSPHRASE,
            salt = TEST_SALT
        )

        // Wrap (encrypt) Secret Key with RSA asymmetric Master Key
        val wrappedSecretKey = cipherWrapper.wrapSecretKey(
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

        // Get Secret Key for encryption
        val secretKey = getSecretKey()

        // Encrypt data with Secret Key
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

        // Get Secret Key for decryption
        val secretKey = getSecretKey()

        // Decrypt data with Secret Key
        val decryptedData = cipherWrapper.decrypt(
            data = Base64.decode(data, Base64.DEFAULT),
            secretKey = secretKey
        )

        return String(decryptedData)
    }

    fun removeKeysMaterials() {
        keyStoreWrapper.deleteAndroidKeyStoreAsymmetricKeyPair()
    }

    private fun getSecretKey(): SecretKey {

        // Get RSA asymmetric Master Key from AndroidKeystore
        val masterKey = keyStoreWrapper.getAndroidKeyStoreAsymmetricKeyPair()
                ?: throw IllegalStateException("There is no master key in AndroidKeyStore")

        // Get wrapped (encrypted) Secret Key from local Storage
        val wrappedSecretKey = storage.getWrappedSecretKey()
                ?: throw IllegalStateException("There is no encrypted secret key in local Storage")

        // Unwrap (decrypt) Secret Key with RSA Private Key
        return cipherWrapper.unWrapSecretKey(
            keyToBeUnWrapped = Base64.decode(wrappedSecretKey, Base64.DEFAULT),
            keyToUnWrapWith = masterKey.private
        )
    }
}