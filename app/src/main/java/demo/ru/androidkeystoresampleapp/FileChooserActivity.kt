package demo.ru.androidkeystoresampleapp

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.util.Log
import android.view.View
import demo.ru.androidkeystoresampleapp.provider.DependencyProvider

class FileChooserActivity : AppCompatActivity() {

    companion object {
        private const val CHOOSE_FILE_REQUEST = 1

        fun startActivity(context: Context) {
            val intent = Intent(context, FileChooserActivity::class.java)
            context.startActivity(intent)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_file_chooser)

        val chooseFileButton = findViewById<View>(R.id.choose_file)
        val decryptFileButton = findViewById<View>(R.id.decrypt_file)

        chooseFileButton.setOnClickListener {
            performFileChoosing()
        }

        decryptFileButton.setOnClickListener {
            performFileDecryption()
        }
    }

    private fun performFileChoosing() {

        // ACTION_OPEN_DOCUMENT is the intent to choose a file via the system's file browser.
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT)

        // Filter to only show results that can be "opened", such as a
        // file (as opposed to a list of contacts or timezones)
        intent.addCategory(Intent.CATEGORY_OPENABLE)

        // Filter to show only images, using the image MIME data type.
        // If one wanted to search for ogg vorbis files, the type would be "audio/ogg".
        // To search for all documents available via installed storage providers,
        // it would be "*/*".
        intent.type = "*/*"

        startActivityForResult(intent, CHOOSE_FILE_REQUEST)
    }

    private fun performFileDecryption() {

        val secretManager = DependencyProvider.getSecretManager(this)

        secretManager.decryptFileAndSaveToFilesDir(
            encryptedFileName = "encrypted_pdf.pdf",
            decryptedFileName = "decrypted_pdf.pdf"
        )
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode != CHOOSE_FILE_REQUEST || resultCode != Activity.RESULT_OK) {
            return
        }

        val dataUri = data?.data ?: return
        Log.d(MainActivity.TAG, "Chose data uri: $dataUri")

        val secretManager = DependencyProvider.getSecretManager(this)
        secretManager.encryptFileAndSaveToFilesDir(dataUri, fileName = "encrypted_pdf.pdf")
    }
}