package mpei.lab1

import javafx.scene.control.Alert
import org.bouncycastle.x509.X509V3CertificateGenerator
import java.io.*
import java.math.BigInteger
import java.security.*
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.security.auth.x500.X500Principal
import kotlin.random.Random

open class Crypto() {
    fun createAlert(msg: String, header: String, type: Alert.AlertType) {
        val alert = Alert(type)
        alert.headerText = header
        alert.contentText = msg
        alert.showAndWait()
    }

    fun createKeyPair(keyStore: KeyStore, name: String, alg: String, sign: String) {
        val rnd = Random
        val keyPairGenerator = KeyPairGenerator.getInstance(alg)
        val keyPair = keyPairGenerator.genKeyPair()
        val gen = X509V3CertificateGenerator()
        val serverCommonName = X500Principal("CN=$name")
        val serverState = X500Principal("ST=Moscow")
        val serverCountry = X500Principal("C=RU")
        val after = Date(2030, 1, 1, 0, 0, 0)
        val before = Date()
        gen.setIssuerDN(serverCommonName)
        gen.setNotBefore(after)
        gen.setNotAfter(before)
        gen.setSubjectDN(serverCommonName)
        gen.setSubjectDN(serverState)
        gen.setSubjectDN(serverCountry)
        gen.setPublicKey(keyPair.public)
        gen.setSignatureAlgorithm(sign)
        gen.setSerialNumber(BigInteger(rnd.nextInt(0, 2000000), java.util.Random()))
        val myCert = gen.generate(keyPair.private)
        keyStore.setKeyEntry("$name $sign", keyPair.private, null, arrayOf(myCert))
    }

    @Throws(MyException::class)
    fun readFile(file: File): ByteArray {
        if (!file.exists()) throw MyException("Файла ${file.name} не существует!")
        val br = BufferedInputStream(FileInputStream(file))
        val arr = br.readBytes()
        br.close()
        return arr
    }

    fun writeFile(file: File, arr: ByteArray) {
        val bw = BufferedOutputStream(FileOutputStream(file))
        bw.write(arr)
        bw.close()
    }

    @Throws(MyException::class)
    fun signEnc(alg: String, arr: ByteArray, name: String): ByteArray {
        if (!File(pathKeyStore).exists()) throw MyException("Отсутствует хранилище ключей!")
        val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
        keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
        if (!keyStore.containsAlias("$name $alg")) throw MyException("Для пользователя $name не существует закрытого ключа!")
        val entryPassword = KeyStore.PasswordProtection(null)
        val privateKeyEntry =
            keyStore.getEntry("$name $alg", entryPassword) as KeyStore.PrivateKeyEntry
        val sign = Signature.getInstance(alg)
        sign.initSign(privateKeyEntry.privateKey, SecureRandom())
        sign.update(arr)
        return sign.sign()
    }

    @Throws(MyException::class)
    fun signDec(alg: String, arr: ByteArray, sign: ByteArray, publicKey: PublicKey) {
        val s = Signature.getInstance(alg)
        s.initVerify(publicKey)
        s.update(arr)
        val k = if (alg == SHA384) "файла" else "открытого ключа"
        if (!s.verify(sign)) throw MyException("Цифровая подпись $k не прошла проверку")
    }

    fun getPublicKey(alias: String): ByteArray {
        if (!File(pathKeyStore).exists()) throw MyException("Отсутствует хранилище ключей!")
        val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
        keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
        if (!keyStore.containsAlias(alias)) throw MyException("Открытого ключа для данного пользователя нет в хранилище")
        val cert = keyStore.getCertificate(alias)
        return cert.publicKey.encoded
    }

    fun generatePublicKey(arr: ByteArray, alg: String): PublicKey {
        val kf = KeyFactory.getInstance(alg)
        val publicKeySpec = X509EncodedKeySpec(arr)
        return kf.generatePublic(publicKeySpec)
    }
}