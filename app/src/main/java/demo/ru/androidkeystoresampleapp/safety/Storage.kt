package demo.ru.androidkeystoresampleapp.safety

import android.content.Context
import android.content.SharedPreferences

/**
 * This class represents simple SharedPreferences Storage.
 */
class Storage(context: Context) {

    companion object {
        private const val STORAGE_NAME = "secret_storage"
        private const val SECRET_KEY: String = "secret_key"
        private const val STRING_DATA_KEY: String = "string_data"
    }

    private val secretPreferences: SharedPreferences

    init {
        secretPreferences = context.getSharedPreferences(STORAGE_NAME, Context.MODE_PRIVATE)
    }

    fun saveSecretKey(wrappedSecretKey: String) {
        secretPreferences.edit()
            .putString(SECRET_KEY, wrappedSecretKey)
            .apply()
    }

    fun getSecretKey(): String? {
        return secretPreferences.getString(SECRET_KEY, null)
    }

    fun deleteSecretKey() {
        secretPreferences.edit()
            .putString(SECRET_KEY, null)
            .apply()
    }

    fun saveStringData(data: String) {
        secretPreferences.edit()
            .putString(STRING_DATA_KEY, data)
            .apply()
    }

    fun getStringData(): String? {
        return secretPreferences.getString(STRING_DATA_KEY, null)
    }
}