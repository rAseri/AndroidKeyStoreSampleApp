package demo.ru.androidkeystoresampleapp.database

import io.realm.Realm
import io.realm.RealmConfiguration

class RealmProvider {

    companion object {

        fun gerRealmInstance(key: ByteArray): Realm {
            val config = RealmConfiguration.Builder()
                .name("myrealm.realm")
                .encryptionKey(key)
                .build()

            return Realm.getInstance(config)
        }
    }
}