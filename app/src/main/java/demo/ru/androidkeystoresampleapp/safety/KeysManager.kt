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
import javax.security.auth.x500.X500Principal

/**
 * This class responsible for providing Keys materials
 */
class KeysManager(private val context: Context) {

    companion object {

        // AndroidKeystore Master Key alias
        private const val MASTER_KEY = "master.key"

        // The names of Security provider
        private const val ANDROID_KEY_STORE_PROVIDER = "AndroidKeyStore"

        // The names of encryption algorithms
        private const val RSA_ALGORITHM = "RSA"
        private const val PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1"

        // Keys sizes
        private const val RSA_KEY_SIZE = 1024
        private const val AES_KEY_SIZE = 256
        private const val REALM_KEY_SIZE = 512
    }

    private val keyStore: KeyStore

    init {
        keyStore = KeyStore.getInstance(ANDROID_KEY_STORE_PROVIDER)
        keyStore.load(null)
    }

    /**
     * Generate and returns 256-bit Secret Key for private data encryption
     */
    fun generateSecretKeyForPrivateData(passphrase: String, salt: ByteArray): SecretKey {
        return generateSecretKeyUsingPassphrase(
            passphrase = passphrase,
            salt = salt,
            keySize = AES_KEY_SIZE
        )
    }

    /**
     * Generate and returns 512-bit Secret Key for Realm Database encryption
     */
    fun generateSecretKeyForRealmDatabase(passphrase: String, salt: ByteArray): SecretKey {
        return generateSecretKeyUsingPassphrase(
            passphrase = passphrase,
            salt = salt,
            keySize = REALM_KEY_SIZE
        )
    }

    /**
     * Generate and returns Secret Key using the [passphrase] and [salt]
     */
    private fun generateSecretKeyUsingPassphrase(
        passphrase: String,
        salt: ByteArray,
        keySize: Int
    ): SecretKey {

        val iterations = 1000

        val secretKeyFactory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM)
        val keySpec = PBEKeySpec(passphrase.toCharArray(), salt, iterations, keySize)
        return secretKeyFactory.generateSecret(keySpec)
    }

    /**
     * Generate and returns new RSA asymmetric KeyPair
     */
    fun generateAndroidKeyStoreAsymmetricKey(): KeyPair {
        val keyPairGenerator =
            KeyPairGenerator.getInstance(RSA_ALGORITHM, ANDROID_KEY_STORE_PROVIDER)

        // Prepare KeyPairGeneratorSpec for init KeyPairGenerator instance
        // ...
        val startDate = Calendar.getInstance()
        val endDate = Calendar.getInstance().apply { add(Calendar.YEAR, 20) }

        // Use deprecated KeyPairGeneratorSpec to support prior 23 SDK versions
        @Suppress("DEPRECATION")
        val builder = KeyPairGeneratorSpec.Builder(context)
            .setAlias(MASTER_KEY)
            .setKeySize(RSA_KEY_SIZE)

            // Asymmetric keys must be signed with a certificate, so we have to
            // set some attributes, required for the `fake` self-signed certificate.
            .setSerialNumber(BigInteger.ONE)
            .setSubject(X500Principal("CN=$MASTER_KEY CA Certificate"))
            .setStartDate(startDate.time)
            .setEndDate(endDate.time)

        // Init KeyPairGenerator instance
        keyPairGenerator.initialize(builder.build())

        // Generates Key with given spec and saves it to the KeyStore
        return keyPairGenerator.generateKeyPair()
    }

    /**
     * Returns RSA asymmetric KeyPair associated with this [alias]
     */
    fun getAndroidKeyStoreAsymmetricKeyPair(): KeyPair? {
        val privateKey = keyStore.getKey(MASTER_KEY, null) as PrivateKey?
        val publicKey = keyStore.getCertificate(MASTER_KEY)?.publicKey

        return if (privateKey != null && publicKey != null) {
            KeyPair(publicKey, privateKey)
        } else {
            null
        }
    }

    fun deleteAndroidKeyStoreAsymmetricKeyPair() {
        keyStore.deleteEntry(MASTER_KEY)
    }
}