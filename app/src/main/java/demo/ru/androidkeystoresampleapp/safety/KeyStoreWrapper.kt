package demo.ru.androidkeystoresampleapp.safety

import android.content.Context
import android.security.KeyPairGeneratorSpec
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.util.*
import javax.security.auth.x500.X500Principal

/**
 * This class responsible for providing Asymmetric Keys material
 */
class KeyStoreWrapper(private val context: Context) {

    companion object {
        private const val KEY_STORE_PROVIDER = "AndroidKeyStore"
        private const val KEY_SIZE = 1024
    }

    private val keyStore: KeyStore

    init {
        keyStore = KeyStore.getInstance(KEY_STORE_PROVIDER)
        keyStore.load(null)
    }

    /**
     * Returns private-public [KeyPair] associated with this [alias]
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

    /**
     * Create new AndroidKeyStore asymmetric [KeyPair]
     */
    fun createAndroidKeyStoreAsymmetricKey(alias: String): KeyPair {
        val generator = KeyPairGenerator.getInstance("RSA", KEY_STORE_PROVIDER)
        initGeneratorWithKeyPairGeneratorSpec(generator, alias)

        // Generates Key with given spec and saves it to the KeyStore
        return generator.generateKeyPair()
    }

    /**
     * Initialize [KeyPairGenerator] that will be used for private-public [KeyPair] generation
     */
    private fun initGeneratorWithKeyPairGeneratorSpec(generator: KeyPairGenerator, alias: String) {
        val startDate = Calendar.getInstance()
        val endDate = Calendar.getInstance()
        endDate.add(Calendar.YEAR, 20)

        // Use deprecated KeyPairGeneratorSpec to support prior 23 SDK devices
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

        generator.initialize(builder.build())
    }
}