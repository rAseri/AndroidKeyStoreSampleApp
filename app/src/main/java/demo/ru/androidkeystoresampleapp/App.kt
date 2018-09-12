package demo.ru.androidkeystoresampleapp

import android.app.Application
import io.realm.Realm

class App : Application() {

    override fun onCreate() {
        super.onCreate()

        // Init Realm
        Realm.init(this)
    }
}