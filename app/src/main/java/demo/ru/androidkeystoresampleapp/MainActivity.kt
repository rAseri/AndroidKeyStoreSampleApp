package demo.ru.androidkeystoresampleapp

import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.util.Log
import android.view.View
import demo.ru.androidkeystoresampleapp.safety.SecretManager
import java.lang.Exception

class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "Debug:"

        private const val TEST_MESSAGE =
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit," +
                    " sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. " +
                    "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris " +
                    "nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in " +
                    "reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur." +
                    " Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia" +
                    " deserunt mollit anim id est laborum."

        private const val ENCRYPTED_MESSAGE = "message"
    }

    private var encryptedMessage: String? = null

    private val secretManager = SecretManager(this)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        encryptedMessage = savedInstanceState?.getString(ENCRYPTED_MESSAGE)

        val encryptButton = findViewById<View>(R.id.encrypt_string)
        val decryptButton = findViewById<View>(R.id.decrypt_string)

        encryptButton.setOnClickListener {
            Log.d(TAG, "Encrypt button clicked")

            try {
                encryptedMessage = secretManager.encryptStringData(TEST_MESSAGE)
                Log.d(TAG, "Encrypted test encryptedMessage: $encryptedMessage")
            } catch (e: Exception) {
                Log.d(TAG, "Error: $e")
            }

        }

        decryptButton.setOnClickListener {
            Log.d(TAG, "Decrypt button clicked")
            val encryptedMessage = encryptedMessage ?: return@setOnClickListener

            try {
                val decryptedMessage = secretManager.decryptStringData(encryptedMessage)
                Log.d(TAG, "Decrypted test encryptedMessage: $decryptedMessage")
            } catch (e: Exception) {
                Log.d(TAG, "Error: $e")
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(ENCRYPTED_MESSAGE, encryptedMessage)
    }
}
