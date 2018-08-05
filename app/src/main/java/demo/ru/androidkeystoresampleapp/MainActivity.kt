package demo.ru.androidkeystoresampleapp

import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.util.Log
import android.view.View
import demo.ru.androidkeystoresampleapp.safety.SecretManager
import demo.ru.androidkeystoresampleapp.safety.Storage
import java.lang.Exception

class MainActivity : AppCompatActivity() {

    companion object {
        const val TAG = "Debug:"

        private const val TEST_MESSAGE =
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit," +
                    " sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. " +
                    "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris " +
                    "nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in " +
                    "reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur." +
                    " Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia" +
                    " deserunt mollit anim id est laborum."

    }

    private lateinit var secretManager: SecretManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val storage = Storage(this)
        secretManager = SecretManager(this, storage)

        val encryptButton = findViewById<View>(R.id.encrypt_string)
        val decryptButton = findViewById<View>(R.id.decrypt_string)

        encryptButton.setOnClickListener {
            Log.d(TAG, "Encrypt button clicked")

            try {
                val encryptedMessage = secretManager.encryptStringData(TEST_MESSAGE)
                Log.d(TAG, "Encrypted test encryptedMessage: $encryptedMessage")

                storage.saveStringData(encryptedMessage)
            } catch (e: Exception) {
                Log.d(TAG, "Error: $e")
            }

        }

        decryptButton.setOnClickListener {
            Log.d(TAG, "Decrypt button clicked")
            val encryptedMessage = storage.getStringData() ?: return@setOnClickListener

            try {
                val decryptedMessage = secretManager.decryptStringData(encryptedMessage)
                Log.d(TAG, "Decrypted test encryptedMessage: $decryptedMessage")
            } catch (e: Exception) {
                Log.d(TAG, "Error: $e")
            }
        }
    }
}
