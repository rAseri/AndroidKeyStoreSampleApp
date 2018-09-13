package demo.ru.androidkeystoresampleapp

import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.util.Log
import android.view.View
import demo.ru.androidkeystoresampleapp.database.model.DogModel
import demo.ru.androidkeystoresampleapp.provider.DependencyProvider
import demo.ru.androidkeystoresampleapp.safety.SecretManager
import io.realm.Realm
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
    private lateinit var realm: Realm

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val storage = DependencyProvider.getStorage(this)
        secretManager = DependencyProvider.getSecretManager(this)

        // Open the realm for the UI thread.
        val realmKey = secretManager.getRealmKey()
        realm = DependencyProvider.gerRealmInstance(realmKey)

        val encryptButton = findViewById<View>(R.id.encrypt_string)
        val decryptButton = findViewById<View>(R.id.decrypt_string)
        val deleteKeyButton = findViewById<View>(R.id.delete_key)
        val addDogButton = findViewById<View>(R.id.add_dog)
        val loadDogsButton = findViewById<View>(R.id.load_dogs)
        val startFileChooserActivityButton = findViewById<View>(R.id.start_file_chooser)

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

        deleteKeyButton.setOnClickListener {
            secretManager.removeKeysMaterials()
        }

        var dogCounter = 0

        addDogButton.setOnClickListener {
            Log.d(TAG, "Add dog button clicked")
            realm.executeTransaction { realm ->
                val dog = DogModel("Dog #${dogCounter++}")
                realm.copyToRealm(dog)
            }
        }

        loadDogsButton.setOnClickListener {
            Log.d(TAG, "Load dogs button clicked")
            val dogs = realm.where(DogModel::class.java).findAll()
            Log.d(TAG, "Loaded dogs: $dogs")
        }

        startFileChooserActivityButton.setOnClickListener {
            FileChooserActivity.startActivity(this)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        realm.close()
    }
}
