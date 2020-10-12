package saml.example.core

import org.apache.commons.io.IOUtils
import java.io.ByteArrayInputStream
import java.io.IOException
import java.security.KeyFactory
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.interfaces.RSAPrivateKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*

object KeyStoreLocator {
    private var certificateFactory: CertificateFactory? = null
    @JvmStatic
	fun createKeyStore(pemPassPhrase: String): KeyStore {
        return try {
            val keyStore = KeyStore.getInstance("JKS")
            keyStore.load(null, pemPassPhrase.toCharArray())
            keyStore
        } catch (e: Exception) {
            throw RuntimeException(e)
        }
    }

    @JvmStatic
	@Throws(IOException::class, NoSuchAlgorithmException::class, InvalidKeySpecException::class, KeyStoreException::class, CertificateException::class)
    fun addPrivateKey(keyStore: KeyStore, alias: String?, privateKey: String, certificate: String, password: String) {
        val wrappedCert = wrapCert(certificate)
        val decodedKey = Base64.getDecoder().decode(privateKey.toByteArray())
        val passwordChars = password.toCharArray()
        val cert = certificateFactory!!.generateCertificate(ByteArrayInputStream(wrappedCert.toByteArray()))
        val certs = ArrayList<Certificate>()
        certs.add(cert)
        val privKeyBytes = IOUtils.toByteArray(ByteArrayInputStream(decodedKey))
        val ks: KeySpec = PKCS8EncodedKeySpec(privKeyBytes)
        val privKey = KeyFactory.getInstance("RSA").generatePrivate(ks) as RSAPrivateKey
        keyStore.setKeyEntry(alias, privKey, passwordChars, certs.toTypedArray())
    }

    private fun wrapCert(certificate: String): String {
        return "-----BEGIN CERTIFICATE-----\n$certificate\n-----END CERTIFICATE-----"
    }

    init {
        certificateFactory = try {
            CertificateFactory.getInstance("X.509")
        } catch (e: CertificateException) {
            throw RuntimeException(e)
        }
    }
}