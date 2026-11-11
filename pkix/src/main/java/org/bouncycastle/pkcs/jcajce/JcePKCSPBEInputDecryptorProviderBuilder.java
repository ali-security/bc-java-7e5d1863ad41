package org.bouncycastle.pkcs.jcajce;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cryptopro.GOST28147Parameters;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.ScryptParams;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.jcajce.PBKDF1Key;
import org.bouncycastle.jcajce.PKCS12KeyWithParameters;
import org.bouncycastle.jcajce.spec.GOST28147ParameterSpec;
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.DefaultSecretKeySizeProvider;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.SecretKeySizeProvider;

public class JcePKCSPBEInputDecryptorProviderBuilder
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();
    private boolean      wrongPKCS12Zero = false;
    private SecretKeySizeProvider keySizeProvider = DefaultSecretKeySizeProvider.INSTANCE;

    public JcePKCSPBEInputDecryptorProviderBuilder()
    {
    }

    public JcePKCSPBEInputDecryptorProviderBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public JcePKCSPBEInputDecryptorProviderBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public JcePKCSPBEInputDecryptorProviderBuilder setTryWrongPKCS12Zero(boolean tryWrong)
    {
        this.wrongPKCS12Zero = tryWrong;

        return this;
    }

    /**
     * Set the lookup provider of AlgorithmIdentifier returning key_size_in_bits used to
     * handle PKCS5 decryption.
     *
     * @param keySizeProvider  a provider of integer secret key sizes.
     *
     * @return the current builder.
     */
    public JcePKCSPBEInputDecryptorProviderBuilder setKeySizeProvider(SecretKeySizeProvider keySizeProvider)
    {
        this.keySizeProvider = keySizeProvider;

        return this;
    }

    public InputDecryptorProvider build(final char[] password)
    {
        return new InputDecryptorProvider()
        {
            private Cipher cipher;
            private AlgorithmIdentifier encryptionAlg;

            public InputDecryptor get(final AlgorithmIdentifier algorithmIdentifier)
                throws OperatorCreationException
            {
                SecretKey key;
                ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();

                try
                {
                    if (algorithm.on(PKCSObjectIdentifiers.pkcs_12PbeIds))
                    {
                        PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algorithmIdentifier.getParameters());

                        cipher = helper.createCipher(algorithm.getId());

                        cipher.init(Cipher.DECRYPT_MODE, new PKCS12KeyWithParameters(password, wrongPKCS12Zero, pbeParams.getIV(), pbeParams.getIterations().intValue()));

                        encryptionAlg = algorithmIdentifier;
                    }
                    else if (algorithm.equals(PKCSObjectIdentifiers.id_PBES2))
                    {
                        PBES2Parameters alg = PBES2Parameters.getInstance(algorithmIdentifier.getParameters());

                        if (MiscObjectIdentifiers.id_scrypt.equals(alg.getKeyDerivationFunc().getAlgorithm()))
                        {
                            ScryptParams params = ScryptParams.getInstance(alg.getKeyDerivationFunc().getParameters());
                            AlgorithmIdentifier encScheme = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

                            // The KDF cost travels in the unauthenticated container, so bound it
                            // before deriving the key to cap the memory-exhaustion vector.
                            checkScryptCost(params);

                            SecretKeyFactory keyFact = helper.createSecretKeyFactory("SCRYPT");

                            key = keyFact.generateSecret(new ScryptKeySpec(password,
                                       params.getSalt(), params.getCostParameter().intValue(), params.getBlockSize().intValue(),
                                       params.getParallelizationParameter().intValue(), keySizeProvider.getKeySize(encScheme)));
                        }
                        else
                        {
                            SecretKeyFactory keyFact = helper.createSecretKeyFactory(alg.getKeyDerivationFunc().getAlgorithm().getId());
                            PBKDF2Params func = PBKDF2Params.getInstance(alg.getKeyDerivationFunc().getParameters());
                            AlgorithmIdentifier encScheme = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

                            if (func.isDefaultPrf())
                            {
                                key = keyFact.generateSecret(new PBEKeySpec(password, func.getSalt(), func.getIterationCount().intValue(), keySizeProvider.getKeySize(encScheme)));
                            }
                            else
                            {
                                key = keyFact.generateSecret(new PBKDF2KeySpec(password, func.getSalt(), func.getIterationCount().intValue(), keySizeProvider.getKeySize(encScheme), func.getPrf()));
                            }
                        }

                        cipher = helper.createCipher(alg.getEncryptionScheme().getAlgorithm().getId());

                        encryptionAlg = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

                        ASN1Encodable encParams = alg.getEncryptionScheme().getParameters();
                        if (encParams instanceof ASN1OctetString)
                        {
                            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ASN1OctetString.getInstance(encParams).getOctets()));
                        }
                        else
                        {
                            // TODO: at the moment it's just GOST, but...
                            GOST28147Parameters gParams = GOST28147Parameters.getInstance(encParams);

                            cipher.init(Cipher.DECRYPT_MODE, key, new GOST28147ParameterSpec(gParams.getEncryptionParamSet(), gParams.getIV()));
                        }
                    }
                    else if (algorithm.equals(PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC)
                        || algorithm.equals(PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC))
                    {
                        PBEParameter pbeParams = PBEParameter.getInstance(algorithmIdentifier.getParameters());

                        cipher = helper.createCipher(algorithm.getId());

                        cipher.init(Cipher.DECRYPT_MODE, new PBKDF1Key(password, PasswordConverter.ASCII),
                                new PBEParameterSpec(pbeParams.getSalt(), pbeParams.getIterationCount().intValue()));
                    }
                    else
                    {
                        throw new OperatorCreationException("unable to create InputDecryptor: algorithm " + algorithm + " unknown.");
                    }
                }
                catch (Exception e)
                {
                    throw new OperatorCreationException("unable to create InputDecryptor: " + e.getMessage(), e);
                }

                return new InputDecryptor()
                {
                    public AlgorithmIdentifier getAlgorithmIdentifier()
                    {
                        return encryptionAlg;
                    }

                    public InputStream getInputStream(InputStream input)
                    {
                        return new CipherInputStream(input, cipher);
                    }
                };
            }
        };
    }

    /**
     * Upper bound, in bytes, on the scrypt working memory (~128 * r * N for the V array and
     * ~128 * r * p for the B array, RFC 7914) honoured when decrypting a PBES2-protected
     * container. The scrypt cost travels in the unauthenticated container, so an unbounded cost
     * is a memory-exhaustion vector. Default 1073741824 (1 GiB).
     */
    private static final String PBE_MAX_SCRYPT_MEMORY = "org.bouncycastle.pbe.max_scrypt_memory";
    private static final int DEFAULT_MAX_SCRYPT_MEMORY = 1 << 30;

    // The KDF cost parameters of a PBES2-protected key arrive in an unauthenticated container, so
    // they are bounded before the (memory/CPU intensive) derivation to cap a decryption-time DoS.
    private static final int MAX_SCRYPT_BLOCK_SIZE = 1024;

    private static void checkScryptCost(ScryptParams params)
        throws IOException
    {
        BigInteger n = params.getCostParameter();
        BigInteger r = params.getBlockSize();
        BigInteger p = params.getParallelizationParameter();

        if (n == null || r == null || p == null
            || n.signum() <= 0 || r.signum() <= 0 || p.signum() <= 0
            || n.bitLength() > 31 || r.bitLength() > 31 || p.bitLength() > 31)
        {
            throw new IOException("invalid scrypt parameters");
        }

        long blockSize = r.longValue();
        if (blockSize > MAX_SCRYPT_BLOCK_SIZE)
        {
            throw new IOException("scrypt block size (" + blockSize + ") greater than " + MAX_SCRYPT_BLOCK_SIZE);
        }

        long maxMemory = getIntProperty(PBE_MAX_SCRYPT_MEMORY, DEFAULT_MAX_SCRYPT_MEMORY);
        // scrypt allocates ~128*r*N bytes (the V array) and ~128*r*p bytes (the B array), RFC 7914.
        // The parallelization parameter p must be bounded as well, otherwise a crafted key with small N
        // and p near the engine's overflow ceiling (~2e6) allocates hundreds of MB past this budget.
        // Bound N and p separately against the budget rather than their sum, so the N limit is
        // preserved exactly (a key with N at the boundary still loads) while p is bounded.
        long maxCost = maxMemory / (128L * blockSize);
        if (n.longValue() > maxCost || p.longValue() > maxCost)
        {
            throw new IOException("scrypt cost parameters require more than " + maxMemory + " bytes");
        }
    }

    private static int getIntProperty(final String propertyName, int defaultValue)
    {
        // Read directly rather than through org.bouncycastle.util.Properties: that class is
        // shipped by the provider jar, which is resolved independently of this one.
        String p = (String)AccessController.doPrivileged(new PrivilegedAction()
        {
            // JDK 1.4 compatibility
            public Object run()
            {
                try
                {
                    return System.getProperty(propertyName);
                }
                catch (AccessControlException e)
                {
                    return null;
                }
            }
        });

        if (p != null)
        {
            return Integer.parseInt(p);
        }

        return defaultValue;
    }
}
