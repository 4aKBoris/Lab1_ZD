package mpei.lab1

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.spec.X509EncodedKeySpec

class Test {
    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            val keyPairGenerator = KeyPairGenerator.getInstance("EC")
            val keyPair = keyPairGenerator.genKeyPair()
            val kf = KeyFactory.getInstance("EC")
            val publicKeySpec = X509EncodedKeySpec(keyPair.public.encoded)
            kf.generatePublic(publicKeySpec)
        }
    }
}