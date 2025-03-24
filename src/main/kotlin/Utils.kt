import java.math.BigInteger
import java.security.SecureRandom
import kotlin.minus

operator fun BigInteger.minus(other: Int): BigInteger = this - BigInteger(other.toString())
fun BigInteger.decodeToString(): String = this.toByteArray().decodeToString()
fun coprime(phi: BigInteger): BigInteger {
    var e = BigInteger("65537")
    while (e.gcd(phi) != BigInteger.ONE)
        e = e.add(BigInteger("2"))
    return e
}

fun ByteArray.modPow(e: BigInteger, n: BigInteger): BigInteger {
    val bigK = BigInteger(1, this)
    val bigG = bigK.modPow(e, n)
    return bigG
}
fun randomPrime(): BigInteger = BigInteger.probablePrime(512, SecureRandom())