package demo.ru.androidkeystoresampleapp.safety

import android.content.Context
import android.security.KeyPairGeneratorSpec
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.util.*
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import javax.security.auth.x500.X500Principal

/**
 * This class responsible for managing and providing of encryption Keys.
 *
 * There are two kinds of Keys:
 *
 * 1. App Secret Key - 256-bit AES [SecretKey] that uses for encryption/decryption of all
 * private app data. This Key should be encrypted and stored in the app private storage.
 *
 * 2. Master KeyPair - 1024-bit RSA asymmetric [KeyPair] that uses only for
 * encryption/decryption of the app Secret Key. This KeyPair is stored in the AndroidKeyStore.
 */
class KeysManager(private val context: Context) {

    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEYSTORE_MASTER_KEY_ALIAS = "master_key"
        private const val KEYSTORE_MASTER_KEY_SIZE = 1024
        private const val SECRET_KEY_SIZE = 256
    }

    private val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)

    init {
        keyStore.load(null)
    }

    /**
     * Generate a Secret Key using a [passphrase] and a [salt]
     */
    fun generateSecretKey(passphrase: String, salt: ByteArray): SecretKey {
        val iterations = 1000
        val password = passphrase.toCharArray()

        val secretKeyFactory = SecretKeyFactory.getInstance(Algorithm.PBKDF2_WITH_HMAC_SHA1)
        val keySpec = PBEKeySpec(password, salt, iterations, SECRET_KEY_SIZE)
        val keyBytes = secretKeyFactory.generateSecret(keySpec).encoded

        return SecretKeySpec(keyBytes, Algorithm.AES)
    }

    /**
     * Generate and save to the AndroidKeyStore new Master KeyPair
     */
    fun generateMasterKeyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance(Algorithm.RSA, KEYSTORE_PROVIDER)

        // Prepare a KeyPairGeneratorSpec for init a KeyPairGenerator instance
        // ...
        val startDate = Calendar.getInstance()
        val endDate = Calendar.getInstance().apply { add(Calendar.YEAR, 20) }

        // Use deprecated KeyPairGeneratorSpec to support prior 23 SDK versions
        @Suppress("DEPRECATION")
        val builder = KeyPairGeneratorSpec.Builder(context)
            .setAlias(KEYSTORE_MASTER_KEY_ALIAS)
            .setKeySize(KEYSTORE_MASTER_KEY_SIZE)

            // Asymmetric RSA KeyPair must be signed with a certificate, so we have to
            // set some attributes, required for the "fake" self-signed certificate.
            .setSerialNumber(BigInteger.ONE)
            .setSubject(X500Principal("CN=$KEYSTORE_MASTER_KEY_ALIAS CA Certificate"))
            .setStartDate(startDate.time)
            .setEndDate(endDate.time)

        // Init the KeyPairGenerator instance
        keyPairGenerator.initialize(builder.build())

        // Generate a KeyPair with the given spec and save it to the AndroidKeyStore
        return keyPairGenerator.generateKeyPair()
    }

    /**
     * Returns a Master KeyPair from the AndroidKeyStore or null
     */
    fun getMasterKeyPair(): KeyPair? {
        val privateKey = keyStore.getKey(KEYSTORE_MASTER_KEY_ALIAS, null) as PrivateKey?
        val publicKey = keyStore.getCertificate(KEYSTORE_MASTER_KEY_ALIAS)?.publicKey

        return if (privateKey != null && publicKey != null) {
            KeyPair(publicKey, privateKey)
        } else {
            null
        }
    }

    /**
     * Delete a Master KeyPair from the AndroidKeyStore
     */
    fun deleteMasterKeyPair() {
        keyStore.deleteEntry(KEYSTORE_MASTER_KEY_ALIAS)
    }
}