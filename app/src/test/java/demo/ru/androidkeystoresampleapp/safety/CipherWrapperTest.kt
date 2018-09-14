package demo.ru.androidkeystoresampleapp.safety

import junit.framework.Assert.assertEquals
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.assertArrayEquals
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.InvalidKeyException
import java.security.Security

/**
 * Set of unit tests for a [CipherWrapper] class
 *
 * Each test contains:
 * 1. "Given" section, where we prepare a test object and test data
 * 2. "When" section, where we run a test method on the test object
 * 3. "Then" section, where we check results
 */
class CipherWrapperTest {

    private val cipherWrapper = CipherWrapper()

    @Before
    fun setUp() {
        // Add the BouncyCastleProvider that will provide all necessary cryptographic algorithms
        Security.addProvider(BouncyCastleProvider())

        // We have to set this property to be able using AES 256-bit Secret Keys
        // on the local machine.
        Security.setProperty("crypto.policy", "unlimited")
    }

    @Test
    fun `Secret Key successfully was wrapped with a Master PublicKey`() {

        // Given
        val secretKey = TestData.testSecretKey
        val masterKeyPair = TestData.testMasterKeyPair

        // When
        val wrappedSecretKey = cipherWrapper.wrapSecretKey(
            keyToBeWrapped = secretKey,
            keyToWrapWith = masterKeyPair.public
        )

        // Then
        assertEquals(true, wrappedSecretKey.isNotEmpty())
        assertEquals(false, secretKey.encoded contentEquals wrappedSecretKey)
    }

    @Test
    fun `Secret Key was successfully unwrapped with correct Master PrivateKey`() {

        // Given
        val secretKey = TestData.testSecretKey
        val masterKeyPair = TestData.testMasterKeyPair

        val wrappedSecretKey = cipherWrapper.wrapSecretKey(
            keyToBeWrapped = secretKey,
            keyToWrapWith = masterKeyPair.public
        )

        // When
        val unwrappedSecretKey = cipherWrapper.unWrapSecretKey(
            keyToBeUnWrapped = wrappedSecretKey,
            keyToUnWrapWith = masterKeyPair.private
        )

        // Then
        assertArrayEquals(secretKey.encoded, unwrappedSecretKey.encoded)
    }

    @Test(expected = InvalidKeyException::class)
    fun `Secret Key wasn't unwrapped with wrong Master PrivateKey`() {

        // Given
        val secretKey = TestData.testSecretKey
        val masterKeyPair = TestData.testMasterKeyPair
        val wrongMasterKeyPair = TestData.testMasterKeyPair

        // When
        val wrappedSecretKey = cipherWrapper.wrapSecretKey(
            keyToBeWrapped = secretKey,
            keyToWrapWith = masterKeyPair.public
        )

        cipherWrapper.unWrapSecretKey(
            keyToBeUnWrapped = wrappedSecretKey,
            keyToUnWrapWith = wrongMasterKeyPair.private
        )

        // Then
        // InvalidKeyException is thrown
    }

    @Test
    fun `Input ByteArray data was successfully encrypted with correct Secret Key`() {

        // Given
        val secretKey = TestData.testSecretKey
        val sourceMessage = "Hello world!"
        val sourceByteArray = sourceMessage.toByteArray()

        // When
        val encryptedMessage = cipherWrapper.encrypt(
            data = sourceByteArray,
            secretKey = secretKey
        )

        // Then
        assertEquals(true, encryptedMessage.isNotEmpty())
        assertEquals(false, sourceByteArray contentEquals encryptedMessage)
    }

    @Test
    fun `Input ByteArray data was successfully decrypted with correct Secret Key`() {

        // Given
        val secretKey = TestData.testSecretKey
        val plainMessage = "Hello world!"
        val plainByteArray = plainMessage.toByteArray(charset = Charsets.UTF_8)

        val encryptedByteArray = cipherWrapper.encrypt(
            data = plainByteArray,
            secretKey = secretKey
        )

        // When
        val decryptedByteArray = cipherWrapper.decrypt(
            data = encryptedByteArray,
            secretKey = secretKey
        )

        val decryptedMessage = decryptedByteArray.toString(charset = Charsets.UTF_8)

        // Then
        assertArrayEquals(plainByteArray, decryptedByteArray)
        assertEquals(plainMessage, decryptedMessage)
    }

    @Test(expected = GeneralSecurityException::class)
    fun `Input ByteArray data wasn't decrypted with wrong Secret Key`() {

        // Given
        val secretKey = TestData.testSecretKey
        val wrongSecretKey = TestData.testSecretKey
        val plainMessage = "Hello world!"
        val plainByteArray = plainMessage.toByteArray(charset = Charsets.UTF_8)

        val encryptedByteArray = cipherWrapper.encrypt(
            data = plainByteArray,
            secretKey = secretKey
        )

        // When
        cipherWrapper.decrypt(
            data = encryptedByteArray,
            secretKey = wrongSecretKey
        )

        // Then
        // Exception is thrown
    }

    @Test
    fun `Input Stream was successfully encrypted with correct Secret Key`() {

        // Given
        val secretKey = TestData.testSecretKey
        val plainMessage = "Hello world!"
        val plainByteArray = plainMessage.toByteArray()

        val plainInputStream = ByteArrayInputStream(plainByteArray)
        val encryptedOutputStream = ByteArrayOutputStream()

        // When
        cipherWrapper.encryptInputStream(
            inputStream = plainInputStream,
            outputStream = encryptedOutputStream,
            secretKey = secretKey
        )

        val encryptedByteArray = encryptedOutputStream.toByteArray()

        // Then
        assertEquals(0, plainInputStream.available())
        assertEquals(true, encryptedByteArray.isNotEmpty())
        assertEquals(false, plainByteArray contentEquals encryptedByteArray)
    }

    @Test
    fun `Input Stream was successfully decrypted with correct Secret Key`() {

        // Given
        val secretKey = TestData.testSecretKey
        val plainMessage = "Hello world!"
        val plainByteArray = plainMessage.toByteArray()

        val plainInputStream = ByteArrayInputStream(plainByteArray)
        val encryptedOutputStream = ByteArrayOutputStream()

        cipherWrapper.encryptInputStream(
            inputStream = plainInputStream,
            outputStream = encryptedOutputStream,
            secretKey = secretKey
        )

        val encryptedByteArray = encryptedOutputStream.toByteArray()

        val encryptedInputStream = ByteArrayInputStream(encryptedByteArray)
        val decryptedOutputStream = ByteArrayOutputStream()

        // When
        cipherWrapper.decryptInputStream(
            inputStream = encryptedInputStream,
            outputStream = decryptedOutputStream,
            secretKey = secretKey
        )

        val decryptedByteArray = decryptedOutputStream.toByteArray()

        // Then
        assertArrayEquals(plainByteArray, decryptedByteArray)
        assertEquals(plainMessage, decryptedByteArray.toString(charset = Charsets.UTF_8))
    }

    @Test(expected = IOException::class)
    fun `Input Stream wasn't decrypted with wrong Secret Key`() {

        // Given
        val secretKey = TestData.testSecretKey
        val wrongSecretKey = TestData.testSecretKey
        val plainMessage = "Hello world!"
        val plainByteArray = plainMessage.toByteArray()

        val plainInputStream = ByteArrayInputStream(plainByteArray)
        val encryptedOutputStream = ByteArrayOutputStream()

        cipherWrapper.encryptInputStream(
            inputStream = plainInputStream,
            outputStream = encryptedOutputStream,
            secretKey = secretKey
        )

        val encryptedByteArray = encryptedOutputStream.toByteArray()

        val encryptedInputStream = ByteArrayInputStream(encryptedByteArray)
        val decryptedOutputStream = ByteArrayOutputStream()

        // When
        cipherWrapper.decryptInputStream(
            inputStream = encryptedInputStream,
            outputStream = decryptedOutputStream,
            secretKey = wrongSecretKey
        )

        // Then
        // Exception is thrown
    }
}