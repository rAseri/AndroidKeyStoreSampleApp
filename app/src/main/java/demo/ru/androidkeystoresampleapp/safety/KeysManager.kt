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
 * This class responsible for providing Keys materials.
 */
class KeysManager(private val context: Context) {

    private val keyStore: KeyStore = KeyStore.getInstance(Constants.KEYSTORE_PROVIDER)

    init {
        keyStore.load(null)
    }

    /**
     * Generate and returns Secret Key using a [passphrase] and a [salt]
     */
    fun generateSecretKey(passphrase: String, salt: ByteArray): SecretKey {
        val iterations = 1000
        val password = passphrase.toCharArray()

        val secretKeyFactory = SecretKeyFactory.getInstance(Constants.PBKDF2_WITH_HMAC_SHA1)
        val keySpec = PBEKeySpec(password, salt, iterations, Constants.SECRET_KEY_SIZE)
        val keyBytes = secretKeyFactory.generateSecret(keySpec).encoded

        return SecretKeySpec(keyBytes, Constants.AES)
    }

    /**
     * Generate and returns new RSA asymmetric KeyPair
     */
    fun generateAndroidKeyStoreAsymmetricKey(): KeyPair {
        val keyPairGenerator =
            KeyPairGenerator.getInstance(Constants.RSA, Constants.KEYSTORE_PROVIDER)

        // Prepare KeyPairGeneratorSpec for init KeyPairGenerator instance
        // ...
        val startDate = Calendar.getInstance()
        val endDate = Calendar.getInstance().apply { add(Calendar.YEAR, 20) }

        // Use deprecated KeyPairGeneratorSpec to support prior 23 SDK versions
        @Suppress("DEPRECATION")
        val builder = KeyPairGeneratorSpec.Builder(context)
            .setAlias(Constants.KEYSTORE_MASTER_KEY_ALIAS)
            .setKeySize(Constants.KEYSTORE_MASTER_KEY_SIZE)

            // Asymmetric keys must be signed with a certificate, so we have to
            // set some attributes, required for the `fake` self-signed certificate.
            .setSerialNumber(BigInteger.ONE)
            .setSubject(X500Principal("CN=${Constants.KEYSTORE_MASTER_KEY_ALIAS} CA Certificate"))
            .setStartDate(startDate.time)
            .setEndDate(endDate.time)

        // Init KeyPairGenerator instance
        keyPairGenerator.initialize(builder.build())

        // Generate a KeyPair with the given spec and save it to the AndroidKeyStore
        return keyPairGenerator.generateKeyPair()
    }

    /**
     * Returns a RSA asymmetric KeyPair from the AndroidKeyStore
     */
    fun getAndroidKeyStoreAsymmetricKeyPair(): KeyPair? {
        val privateKey = keyStore.getKey(Constants.KEYSTORE_MASTER_KEY_ALIAS, null) as PrivateKey?
        val publicKey = keyStore.getCertificate(Constants.KEYSTORE_MASTER_KEY_ALIAS)?.publicKey

        return if (privateKey != null && publicKey != null) {
            KeyPair(publicKey, privateKey)
        } else {
            null
        }
    }

    /**
     * Delete a RSA asymmetric KeyPair from the AndroidKeyStore
     */
    fun deleteAndroidKeyStoreAsymmetricKeyPair() {
        keyStore.deleteEntry(Constants.KEYSTORE_MASTER_KEY_ALIAS)
    }
}