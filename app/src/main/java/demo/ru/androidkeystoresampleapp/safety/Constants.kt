package demo.ru.androidkeystoresampleapp.safety

object Constants {

    const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    const val KEYSTORE_MASTER_KEY_ALIAS = "master_key"
    const val KEYSTORE_MASTER_KEY_SIZE = 1024
    const val SECRET_KEY_SIZE = 256

    const val RSA = "RSA"
    const val AES = "AES"
    const val PBKDF2_WITH_HMAC_SHA1 = "PBKDF2WithHmacSHA1"

    /**
     * The transformation represents the algorithm, that will be used for encryption or decryption,
     * in format of: ”Algorithm/Mode/Padding”
     */
    const val AES_TRANSFORMATION = "AES/CBC/PKCS7Padding"
    const val RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding"
}