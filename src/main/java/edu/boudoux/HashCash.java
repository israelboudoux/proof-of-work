package edu.boudoux;

import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;

public class HashCash {
    
    private static final Logger logger = LoggerFactory.getLogger(HashCash.class);
    
    public static void main(String[] args) {
        /*
         The number of required bit collisions - adjust it to the desired difficulty
         */
        int difficulty = 25;
        
        /*
         The `servicePrefix` can be any string. In the case of Bitcoin, this would be the block's header hash.
         */
        String servicePrefix = "anything!!!";
        
        String nonce = prover(servicePrefix, difficulty);

        boolean isOk = verifier(servicePrefix, difficulty, nonce);

        if (!isOk) {
            logger.error("Wrong `nonce` for the `service_prefix + difficulty` defined");
        } else {
            logger.info("Nonce OK!");
        }
    }

    public static boolean verifier(String servicePrefix, int difficulty, String nonce) {
        return doesDifficultyMatch(hash(servicePrefix + nonce), difficulty);
    }

    private static String hash(String value) {
        return DigestUtils.sha1Hex(value);
    }

    /**
     * Returns a nonce that matches the provided parameters.
     *
     * @param servicePrefix
     * @param difficulty
     * @return
     */
    public static String prover(String servicePrefix, int difficulty) {
        BigInteger nonce = BigInteger.ZERO;

        Instant startingTime = Instant.now();
        Instant finishingTime;
        String hash;
        
        while(true) {
            hash = hash(servicePrefix + nonce.toString(16));

            if(doesDifficultyMatch(hash, difficulty)) {
                finishingTime = Instant.now();
                break;
            }

            nonce = nonce.add(BigInteger.ONE);
        }

        logger.debug("Difficulty: " + difficulty);
        logger.debug(String.format("Nonce found: %d (0x%s)", nonce, nonce.toString(16)));
        logger.debug(String.format("Final hash: %s", hash));
        logger.debug(String.format("Elapsed time: %.3f secs", Duration.between(startingTime, finishingTime).toMillis() / 1000d));

        return nonce.toString(16);
    }

    private static boolean doesDifficultyMatch(String hash, int difficulty) {
        // we're using SHA-1 which outputs a 160 bits hash. Here, after the parsing to BigInteger, the value may
        // already have some 0 MSB that aren't considered in the final number, then we need to calculate the shift precisely
        int totalHashBits = hash.length() * 4;
        BigInteger calculatedHash = new BigInteger(hash, 16);
        int bitsToShift = calculatedHash.bitLength() - (difficulty - (totalHashBits - calculatedHash.bitLength()));

        calculatedHash = calculatedHash.shiftRight(bitsToShift);

        return calculatedHash.equals(BigInteger.ZERO);
    }
}
