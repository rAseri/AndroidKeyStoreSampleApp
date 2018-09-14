package demo.ru.androidkeystoresampleapp.safety

import java.security.KeyPair
import java.security.KeyPairGenerator
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

object TestData {

    private const val TEST_KEY_SIZE = 256
    private const val TEST_MASTER_KEY_PAIR_SIZE = 1024

    val testSecretKey: SecretKey
        get() {
            val keyGen = KeyGenerator.getInstance(Algorithm.AES)
            keyGen.init(TEST_KEY_SIZE)
            return keyGen.generateKey()
        }

    val testMasterKeyPair: KeyPair
        get() {
            val keyGen = KeyPairGenerator.getInstance(Algorithm.RSA)
            keyGen.initialize(TEST_MASTER_KEY_PAIR_SIZE)
            return keyGen.genKeyPair()
        }
}