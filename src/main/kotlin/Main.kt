import java.math.BigInteger
import java.util.Base64

fun main() {
    val keypair = generateRSAKey()
    print("Emter a message: ")
    val message = readln()

    val encrypted = encrypt(keypair.public, message)
    val decrypted = decrypt(keypair.private, encrypted)

    println("Message: $message")
    println("Encrypted: $encrypted")
    println("Decrypted: $decrypted")
}

data class PublicRSAKey(val e: BigInteger, val n: BigInteger)
data class PrivateRSAKey(val d: BigInteger, val n: BigInteger)
data class RSAKeypair(val public: PublicRSAKey, val private: PrivateRSAKey)

fun generateRSAKey(): RSAKeypair {
    val p = randomPrime()
    val q = randomPrime()

    val n = p * q
    val phi = (p-1) * (q-1)

    val e = coprime(phi)
    val d = e.modInverse(phi)

    val publicKey = PublicRSAKey(e, n)
    val privateKey = PrivateRSAKey(d, n)

    return RSAKeypair(publicKey, privateKey)
}

fun encrypt(publicKey: PublicRSAKey, plainText: String): String {
    val k = plainText.encodeToByteArray()
    val g = k.modPow(publicKey.e, publicKey.n)
    return Base64.getEncoder().encodeToString(g.toByteArray())
}

fun decrypt(privateKey: PrivateRSAKey, encryptedText: String): String {
    val k = Base64.getDecoder().decode(encryptedText)
    val g = k.modPow(privateKey.d, privateKey.n)
    return g.decodeToString()
}