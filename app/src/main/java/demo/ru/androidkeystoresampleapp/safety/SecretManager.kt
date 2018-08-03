package demo.ru.androidkeystoresampleapp.safety

import android.content.Context
import android.util.Base64

class SecretManager(context: Context) {

    companion object {
        private const val ALIAS = "safety.key"
        private val defaultCharsets = Charsets.UTF_8
    }

    private val cipherWrapper = CipherWrapper()
    private val keyStoreWrapper = KeyStoreWrapper(context)

    init {
        if (keyStoreWrapper.getAndroidKeyStoreAsymmetricKeyPair(ALIAS) == null) {
            keyStoreWrapper.createAndroidKeyStoreAsymmetricKey(ALIAS)
        }
    }

    fun encryptStringData(plainData: String): String {
        val plainBytes = plainData.toByteArray(defaultCharsets)

        val key = keyStoreWrapper.getAndroidKeyStoreAsymmetricKeyPair(ALIAS)
                ?: throw IllegalStateException("The key is null")

        val encryptedBytes = cipherWrapper.encrypt(plainBytes, key.public)
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }

    fun decryptStringData(encryptedData: String): String {
        val encryptedBytes = Base64.decode(encryptedData, Base64.DEFAULT)

        val key = keyStoreWrapper.getAndroidKeyStoreAsymmetricKeyPair(ALIAS)
                ?: throw IllegalStateException("The key is null")

        val decryptedBytes = cipherWrapper.decrypt(encryptedBytes, key.private)
        return String(decryptedBytes)
    }
}