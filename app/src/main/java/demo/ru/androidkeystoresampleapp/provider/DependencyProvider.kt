package demo.ru.androidkeystoresampleapp.provider

import android.content.Context
import demo.ru.androidkeystoresampleapp.safety.SecretManager
import demo.ru.androidkeystoresampleapp.safety.Storage
import io.realm.Realm
import io.realm.RealmConfiguration

object DependencyProvider {

    private var storage: Storage? = null
    private var secretManager: SecretManager? = null

    fun getStorage(context: Context): Storage {
        var storage = this.storage

        if (storage == null) {
            storage = Storage(context.applicationContext)
            this.storage = storage
        }

        return storage
    }

    fun getSecretManager(context: Context): SecretManager {
        var secretManager = this.secretManager

        if (secretManager == null) {
            val storage = getStorage(context.applicationContext)
            secretManager = SecretManager(context.applicationContext, storage)
            this.secretManager = secretManager
        }

        return secretManager
    }

    fun gerRealmInstance(key: ByteArray): Realm {
        val config = RealmConfiguration.Builder()
            .name("myrealm.realm")
            .encryptionKey(key)
            .build()

        return Realm.getInstance(config)
    }
}