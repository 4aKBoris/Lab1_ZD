import mpei.lab1.*
import org.jetbrains.annotations.TestOnly
import java.io.File
import java.io.FileInputStream
import java.security.KeyStore

class Test {

    companion object {
        var cr = Crypto()
        @JvmStatic
        fun main(args: Array<String>) {
            Test()
        }
    }

    init {
        testFun()
        testFun2()
    }

    private fun testFun() {
        val name = "losev"
        val str = "d43rt089w47ud 28r437gy8943yfr97834yut259gu583w4h5"
        val sign = cr.signEnc(SHA384, str.toByteArray(Charsets.UTF_8), name)
        val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
        keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
        val cert = keyStore.getCertificate("$name $SHA384")
        println(cr.signDec(SHA384, str.toByteArray(Charsets.UTF_8), sign, cert.publicKey))
    }

    @TestOnly
    private fun testFun2() {
        val name = "losev"
        var arr = cr.readFile(File("PK/$name.pub"))
        println(arr.size)
        val a = arr
        val s1 = arr[0].toInt()
        val s2 = arr[1].toInt()
        val login = arr.copyOfRange(2, 2 + s1)
        println(login.toString(Charsets.UTF_8))
        println(arr.size)
        val key = arr.copyOfRange(2 + s1, 2 + s1 + s2)
        println(key.toList())
        println(arr.size)
        println(arr.toList())
        val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
        keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
        val cert = keyStore.getCertificate("$name $SHA1")
        println(a.copyOf(2 + s1 + s2))
        cr.signDec(SHA1, a.copyOf(2 + s1 + s2), arr.copyOfRange(2 + s1 + s2, arr.size), cert.publicKey)
    }

    @TestOnly
    private fun testFun3() {
        val name = "losev"
        var arr = cr.readFile(File("losev.txt")).toMutableList()
        val a = arr
        val s1 = arr.removeFirst().toInt()
        val s2 = arr.removeFirst().toInt()
        val login = arr.take(s1)
        println(login.toByteArray().toString(Charsets.UTF_8))
        arr = arr.drop(s1) as MutableList<Byte>
        val sign = arr.take(s2)
        println(sign)
        arr = arr.drop(s2) as MutableList<Byte>
        val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
        keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
        val cert = keyStore.getCertificate("$name $SHA384")
        cr.signDec(SHA384, arr.toByteArray(), sign.toByteArray(), cert.publicKey)
        println(arr.toByteArray().toString(Charsets.UTF_8))
        println(sign)
    }
}