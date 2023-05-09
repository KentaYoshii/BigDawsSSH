package protocol

import (
        "crypto/dsa"
        "crypto/rand"
        "crypto/sha1"
        "crypto/x509"
        "encoding/asn1"
        "encoding/pem"
        "errors"
        "io/ioutil"
        "math/big"
        "os"
)

type dsaSignature struct {
        R, S *big.Int
}

func ReadFile(file string) ([]byte, error) {
        f, err := os.Open(file)
        if err != nil {
                return nil, err
        }

        return ioutil.ReadAll(f)
}

// ParseDSAPrivateKey returns a DSA private key from its ASN.1 DER encoding, as
// specified by the OpenSSL DSA man page.
func DSAParseDSAPrivateKey(der []byte) (*dsa.PrivateKey, error) {
        var k struct {
                Version int
                P       *big.Int
                Q       *big.Int
                G       *big.Int
                Pub     *big.Int
                Priv    *big.Int
        }
        rest, err := asn1.Unmarshal(der, &k)
        if err != nil {
                return nil, errors.New("failed to parse DSA key: " + err.Error())
        }
        if len(rest) > 0 {
                return nil, errors.New("garbage after DSA key")
        }

        return &dsa.PrivateKey{
                PublicKey: dsa.PublicKey{
                        Parameters: dsa.Parameters{
                                P: k.P,
                                Q: k.Q,
                                G: k.G,
                        },
                        Y: k.Pub,
                },
                X: k.Priv,
        }, nil
}

func ParseDSAPublicKey(der []byte) (*dsa.PublicKey, error) {
        pub, err := x509.ParsePKIXPublicKey(der)
        if err != nil {
                return nil, err
        }

        switch pub := pub.(type) {
        case *dsa.PublicKey:
                return pub, nil
        default:
                return nil, errors.New("invalid type of public key")
        }
}

func ParseDSAPrivateKeyFromFile(path string) (*dsa.PrivateKey, error) {
        chunk, err := ReadFile(path)
        if err != nil {
                return nil, err
        }

        block, _ := pem.Decode(chunk)
        if err != nil {
                return nil, errors.New("failed to parse PEM block")
        }
        return DSAParseDSAPrivateKey(block.Bytes)
}

func ParseDSAPublicKeyFromFile(path string) (*dsa.PublicKey, error) {
        chunk, err := ReadFile(path)
        if err != nil {
                return nil, err
        }

        block, _ := pem.Decode(chunk)
        if err != nil {
                return nil, errors.New("failed to parse PEM block")
        }
        return ParseDSAPublicKey(block.Bytes)
}

func ParseSignatureFromFile(path string) (*big.Int, *big.Int, error) {
        chunk, err := ReadFile(path)
        if err != nil {
                return nil, nil, err
        }
        var s dsaSignature

        rest, err := asn1.Unmarshal(chunk, &s)
        if err != nil {
                return nil, nil, errors.New("failed to parse signature: " + err.Error())
        }
        if len(rest) > 0 {
                return nil, nil, errors.New("garbage after signature")
        }
        return s.R, s.S, nil
}

func DSAParseSignatureFromBytes(data []byte) (*big.Int, *big.Int, error) {
        var s dsaSignature
        rest, err := asn1.Unmarshal(data, &s)
        if err != nil {
                return nil, nil, errors.New("failed to parse signature: " + err.Error())
        }
        if len(rest) > 0 {
                return nil, nil, errors.New("garbage after signature")
        }
        return s.R, s.S, nil
}

func Hash(file string) ([]byte, error) {
        chunk, err := ReadFile(file)
        if err != nil {
                return nil, err
        }

        sum := sha1.Sum(chunk)
        return sum[:], nil
}

func DSASign(hash []byte, priKey *dsa.PrivateKey) ([]byte, error) {
        var err error
        var s dsaSignature
        s.R, s.S, err = dsa.Sign(rand.Reader, priKey, hash)
        if err != nil {
                return nil, err
        }

        return asn1.Marshal(s)
}

func DSAVerifyWithSigFile(hash []byte, keyFile string, signatureFile string) ([]byte, error) {
        pub, err := ParseDSAPublicKeyFromFile(keyFile)
        if err != nil {
                return nil, err
        }

        r, s, err := ParseSignatureFromFile(signatureFile)
        if err != nil {
                return nil, err
        }

        if dsa.Verify(pub, hash, r, s) {
                return []byte("Verified OK\n"), nil
        } else {
                return nil, errors.New("verification Failure")
        }
}

func DSAVerify(hash []byte, pub *dsa.PublicKey, sig[]byte) ([]byte, error) {
        r, s, err := DSAParseSignatureFromBytes(sig)
        if err != nil {
                return nil, err
        }

        if dsa.Verify(pub, hash, r, s) {
                return []byte("Verified OK\n"), nil
        } else {
                return nil, errors.New("verification Failure")
        }
}
