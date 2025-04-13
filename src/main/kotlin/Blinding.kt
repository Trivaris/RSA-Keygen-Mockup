import Blinding.generateBlindingFactor
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.engines.RSABlindedEngine
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Security
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PublicKeyFactory
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey

data class BCKeyPair(
    val public: RSAKeyParameters,
    val private: RSAPrivateCrtKeyParameters
)

fun KeyPair.toBCKeyPair(): BCKeyPair {
    val publicKey = this.public as RSAPublicKey
    val privateKey = this.private as RSAPrivateCrtKey

    return BCKeyPair(
        public = PublicKeyFactory.createKey(publicKey.encoded) as RSAKeyParameters,
        private = PrivateKeyFactory.createKey(privateKey.encoded) as RSAPrivateCrtKeyParameters
    )
}

data class BlindedMessage(
    val message: ByteArray,
    val blindingFactor: BigInteger
)

object Blinding {

    fun verifySignature(publicKey: RSAKeyParameters, message: ByteArray, signature: ByteArray): Boolean {
        val verifier = RSABlindedEngine()
        verifier.init(false, publicKey)
        val result = verifier.processBlock(signature, 0, signature.size)
        return result.contentEquals(message)
    }

    fun generateBlindingFactor(publicKey: RSAKeyParameters): BigInteger {
        val n = publicKey.modulus
        val random = SecureRandom()
        var r: BigInteger

        do {
            r = BigInteger(n.bitLength(), random)
        } while (r <= BigInteger.ONE || r >= n || !r.gcd(n).equals(BigInteger.ONE))

        return r
    }

    fun hashMessage(message: ByteArray): ByteArray {
        val digest = SHA256Digest()
        digest.update(message, 0, message.size)
        val hash = ByteArray(digest.digestSize)
        digest.doFinal(hash, 0)
        return hash
    }
}

fun genKeypair(): BCKeyPair {
    val keyGen = KeyPairGenerator.getInstance("RSA", "BC")
    keyGen.initialize(2048)
    return keyGen.generateKeyPair().toBCKeyPair()
}

fun main() {
    Security.addProvider(BouncyCastleProvider())
    val message = "Blind me!".toByteArray()

    val blinded = Voter.blindMessage(message)
    val blindSignature = Host.signBlindedMessage(blinded.message)
    val signature = Voter.unblindSignature(Voter.keypair.public, blindSignature, blinded.blindingFactor)

    val valid = Blinding.verifySignature(Host.keypair.public, message, signature)

    println("Is the blind signature valid? $valid")
}

object Voter {
    val keypair = genKeypair()

    fun blindMessage(message: ByteArray): BlindedMessage {
        val publicKey = keypair.public

        val r = generateBlindingFactor(publicKey)
        val n = publicKey.modulus
        val e = publicKey.exponent

        val m = BigInteger(1, message)
        val blinded = m.multiply(r.modPow(e, n)).mod(n)

        return BlindedMessage(
            blinded.toByteArray(),
            r
        )
    }

    fun unblindSignature(publicKey: RSAKeyParameters, blindSignature: ByteArray, r: BigInteger): ByteArray {
        val n = publicKey.modulus
        val s = BigInteger(1, blindSignature)
        val rInv = r.modInverse(n)
        val unblinded = s.multiply(rInv).mod(n)
        return unblinded.toByteArray()
    }
}

object Host {
    val keypair = genKeypair()

    fun signBlindedMessage(blindedMessage: ByteArray): ByteArray {
        val signer = RSABlindedEngine()
        signer.init(true, keypair.private)
        return signer.processBlock(blindedMessage, 0, blindedMessage.size)
    }
}