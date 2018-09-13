package demo.ru.androidkeystoresampleapp.safety

import android.content.Context
import android.util.Base64
import java.security.PublicKey
import javax.crypto.SecretKey

/**
 * This class is a simple Facade for the app secrets managing.
 *
 * This class responsible for performing encryption and decryption user data,
 * initial keys generation etc.
 */
class SecretManager(context: Context, private val storage: Storage) {

    companion object {
        private const val TEST_USER_PASSPHRASE = "4423"
        private val TEST_SALT = byteArrayOf(1, 2, 3)
    }

    private val cipherWrapper = CipherWrapper()
    private val keyStoreWrapper = KeysManager(context)

    init {
        var masterKeyPair = keyStoreWrapper.getMasterKeyPair()

        // NOTE: Master KeyPair may be null when a user is changing device protection mode
        if (masterKeyPair == null) {

            // Generate Master KeyPair
            masterKeyPair = keyStoreWrapper.generateMasterKeyPair()

            // Generate Secret Key, wrap (encrypt) it with the Master PublicKey
            // and save it to the local Storage
            generateAndSaveSecretKey(masterPublicKey = masterKeyPair.public)

        } else if (storage.getSecretKey() == null) {

            // Generate Secret Key, wrap (encrypt) it with Master PublicKey
            // and save it to the local Storage
            generateAndSaveSecretKey(masterPublicKey = masterKeyPair.public)
        }
    }

    private fun generateAndSaveSecretKey(masterPublicKey: PublicKey) {

        // Generate a Secret Key
        val secretKey = keyStoreWrapper.generateSecretKey(
            passphrase = TEST_USER_PASSPHRASE,
            salt = TEST_SALT
        )

        // Wrap (encrypt) Secret Key with Master PublicKey
        val wrappedSecretKey = cipherWrapper.wrapSecretKey(
            keyToBeWrapped = secretKey,
            keyToWrapWith = masterPublicKey
        )

        // Save the Secret Key to the local Storage
        storage.saveSecretKey(
            wrappedSecretKey = Base64.encodeToString(wrappedSecretKey, Base64.DEFAULT)
        )
    }

    /**
     * Encrypt String data and returns its Base64 representation
     *
     * [data] - String data to be encrypted
     */
    fun encryptStringData(data: String): String {

        // Get a Secret Key for encryption
        val secretKey = getSecretKey()

        // Encrypt String data with the Secret Key
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

        // Get a Secret Key for decryption
        val secretKey = getSecretKey()

        // Decrypt String data with the Secret Key
        val decryptedData = cipherWrapper.decrypt(
            data = Base64.decode(data, Base64.DEFAULT),
            secretKey = secretKey
        )

        return String(decryptedData)
    }

    /**
     * Returns [ByteArray] representation of Key that is used by Realm.
     *
     * Note: Realm requires 512-bit Key for Database encryption, so we just double
     * the app Secret Key to 512-bit.
     */
    fun getRealmKey(): ByteArray {
        val secretKeyEncoded = getSecretKey().encoded
        return secretKeyEncoded + secretKeyEncoded
    }

    private fun getSecretKey(): SecretKey {

        // Get Master KeyPair
        val masterKey = keyStoreWrapper.getMasterKeyPair()
                ?: throw IllegalStateException("There is no master key in the AndroidKeyStore")

        // Get wrapped (encrypted) Secret Key from the local Storage
        val wrappedSecretKey = storage.getSecretKey()
                ?: throw IllegalStateException("There is no encrypted secret key in th local Storage")

        // Unwrap (decrypt) Secret Key with a Master PrivateKey
        return cipherWrapper.unWrapSecretKey(
            keyToBeUnWrapped = Base64.decode(wrappedSecretKey, Base64.DEFAULT),
            keyToUnWrapWith = masterKey.private
        )
    }

    fun removeKeysMaterials() {
        keyStoreWrapper.deleteMasterKeyPair()
        storage.deleteSecretKey()
    }
}