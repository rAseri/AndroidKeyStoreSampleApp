package demo.ru.androidkeystoresampleapp.safety

import android.content.Context
import android.content.SharedPreferences

class Storage(context: Context) {

    companion object {
        private const val STORAGE_NAME = "secrets"
        private const val STORAGE_WRAPPED_SECRET_KEY: String = "encryption_key"
        private const val STORAGE_STRING_DATA_KEY: String = "data"
    }

    private val secretPreferences: SharedPreferences

    init {
        secretPreferences = context.getSharedPreferences(STORAGE_NAME, Context.MODE_PRIVATE)
    }

    fun saveWrappedSecretKey(wrappedSecretKey: String) {
        secretPreferences.edit()
            .putString(STORAGE_WRAPPED_SECRET_KEY, wrappedSecretKey)
            .apply()
    }

    fun getWrappedSecretKey(): String? {
        return secretPreferences.getString(STORAGE_WRAPPED_SECRET_KEY, null)
    }

    fun saveStringData(data: String) {
        secretPreferences.edit()
            .putString(STORAGE_STRING_DATA_KEY, data)
            .apply()
    }

    fun getStringData(): String? {
        return secretPreferences.getString(STORAGE_STRING_DATA_KEY, null)
    }
}