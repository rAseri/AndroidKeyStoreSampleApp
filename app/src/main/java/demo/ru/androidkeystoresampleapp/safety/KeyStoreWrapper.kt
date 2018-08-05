package demo.ru.androidkeystoresampleapp.safety

import android.content.Context
import android.security.KeyPairGeneratorSpec
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.util.*
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.security.auth.x500.X500Principal

/**
 * This class responsible for providing Keys materials and generating
 * new symmetric / asymmetric Keys
 */
class KeyStoreWrapper(private val context: Context) {

    companion object {

        // The names of Security providers
        private const val ANDROID_KEY_STORE_PROVIDER = "AndroidKeyStore"
        private const val BOUNCY_CASTLE_PROVIDER = "BC"

        // The names of encryption algorithms
        private const val AES_ALGORITHM = "AES"
        private const val RSA_ALGORITHM = "RSA"

        // RSA asymmetric key size
        private const val KEY_SIZE = 1024
    }

    private val keyStore: KeyStore

    init {
        keyStore = KeyStore.getInstance(ANDROID_KEY_STORE_PROVIDER)
        keyStore.load(null)
    }

    /**
     * Generate and returns new AES symmetric Secret Key
     */
    fun generateDefaultSymmetricKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM, BOUNCY_CASTLE_PROVIDER)
        return keyGenerator.generateKey()
    }

    /**
     * Generate and returns new RSA asymmetric KeyPair
     */
    fun generateAndroidKeyStoreAsymmetricKey(alias: String): KeyPair {
        val keyPairGenerator =
            KeyPairGenerator.getInstance(RSA_ALGORITHM, ANDROID_KEY_STORE_PROVIDER)

        // Prepare KeyPairGeneratorSpec for init KeyPairGenerator instance
        // ...
        val startDate = Calendar.getInstance()
        val endDate = Calendar.getInstance().apply { add(Calendar.YEAR, 20) }

        // Use deprecated KeyPairGeneratorSpec to support prior 23 SDK versions
        @Suppress("DEPRECATION")
        val builder = KeyPairGeneratorSpec.Builder(context)
            .setAlias(alias)
            .setKeySize(KEY_SIZE)

            // Asymmetric keys must be signed with a certificate, so we have to
            // set some attributes, required for the `fake` self-signed certificate.
            .setSerialNumber(BigInteger.ONE)
            .setSubject(X500Principal("CN=$alias CA Certificate"))
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
    fun getAndroidKeyStoreAsymmetricKeyPair(alias: String): KeyPair? {
        val privateKey = keyStore.getKey(alias, null) as PrivateKey?
        val publicKey = keyStore.getCertificate(alias)?.publicKey

        return if (privateKey != null && publicKey != null) {
            KeyPair(publicKey, privateKey)
        } else {
            null
        }
    }
}