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
func ParseDSAPrivateKey(der []byte) (*dsa.PrivateKey, error) {
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
        return ParseDSAPrivateKey(block.Bytes)
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

func ParseSignatureFromBytes(data []byte) (*big.Int, *big.Int, error) {
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

func Sign(hash []byte, keyFile string) ([]byte, error) {
        priv, err := ParseDSAPrivateKeyFromFile(keyFile)
        if err != nil {
                return nil, err
        }

        var s dsaSignature
        s.R, s.S, err = dsa.Sign(rand.Reader, priv, hash)
        if err != nil {
                return nil, err
        }

        return asn1.Marshal(s)
}

func VerifyWithSigFile(hash []byte, keyFile string, signatureFile string) ([]byte, error) {
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
                return nil, errors.New("Verification Failure")
        }
}

func Verify(hash []byte, keyFile string, sig[]byte) ([]byte, error) {
        pub, err := ParseDSAPublicKeyFromFile(keyFile)
        if err != nil {
                return nil, err
        }

        r, s, err := ParseSignatureFromBytes(sig)
        if err != nil {
                return nil, err
        }

        if dsa.Verify(pub, hash, r, s) {
                return []byte("Verified OK\n"), nil
        } else {
                return nil, errors.New("Verification Failure")
        }
}

// func main() {
//         file := flag.String("file", "", "file to sign")
//         action := flag.String("action", "sign", "sign or verify")
//         privKeyFile := flag.String("key", "", "private key")
//         pubKeyFile := flag.String("pubkey", "", "public key")
//         signatureFile := flag.String("signature", "", "signature to verify")
//         flag.Parse()

//         hash, err := hash(*file)
//         if err != nil {
//                 log.Fatal("hash:", err)
//         }

//         var out []byte
//         switch *action {
//         case "sign":
//                 out, err = sign(hash, *privKeyFile)
//         case "verify":
//                 out, err = verify(hash, *pubKeyFile, *signatureFile)
//         default:
//                 err = errors.New("unknown action")
//         }

//         if err != nil {
//                 log.Fatalf("%s: %s", *action, err)
//         }
//         os.Stdout.Write(out)
// }