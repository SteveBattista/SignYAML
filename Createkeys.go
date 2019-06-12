package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/yaml.v2"
	"io"
	"log"
	"math/big"
	"os"
	"syscall"
)

type PrivateData struct {
	D *big.Int `yaml:"EncrypotedD"`
	S *big.Int `yaml:"Salt"`
	N *big.Int `yaml:"Nonce"`
	X *big.Int `yaml:"Mx"`
	Y *big.Int `yaml:"My"`
}

type PublicData struct {
	X *big.Int `yaml:"Mx"`
	Y *big.Int `yaml:"My"`
}

func main() {

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalln(err.Error())
	}
	publicKey := privateKey.PublicKey

	ciphertext, nonce, salt := encryptKey(privateKey.D)

	fmt.Printf("Writing Private key\n")
	printPrivateKey(&publicKey, nonce, ciphertext, salt)

	fmt.Printf("Writing Public key\n")
	printPubicKey(&publicKey)

}

func encryptKey(privateKeyD *big.Int) (ciphertext []byte, nonce []byte, salt []byte) {
	keyLen := 32
	saltLen := 32
	nonceLen := 12
	/*https://www.ietf.org/rfc/rfc2898.txt states that this should be at least 8 octets long. The goal is to prevent re-use
	  since 256 is the new hotness (2018-2019) why not make a salt that is 256 bits. It is impossilbe (not enough energy in the universe) to create rainbow tables for 2^256
	  salts. */
	salt = make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		log.Fatalln(err.Error())
	}
	/* See https://blog.filippo.io/the-scrypt-parameters/ for N value
	   The combonation of the salt and the N value is overkill for reversing.
	   I also wanted to make this fast so that the check can be done per reading of a YAML file to reduce TOCTOU race conditions
	   The decrypted key could still be in memory to speed things up. Hopefully the pass-phrase would be kept in memory, you don't want to have to type the passowrd 100 times.
	*/

	fmt.Println("Enter in PassPhrase to generate key to encrypt private key")
	passPhrasebyte, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalln(err.Error())
	}
	key, err := scrypt.Key(passPhrasebyte, salt, 32768, 8, 1, keyLen)
	if err != nil {
		log.Fatalln(err.Error())
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatalln(err.Error())
	}
	// Never use more than 2^32 random nonces with the same key because of the risk of a repeat. https://tools.ietf.org/html/rfc7539 requires a 96 bit nonce
	nonce = make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalln(err.Error())
	}
	//   fmt.Printf("Plaintext %d \n", privateKeyD.Bytes())
	ciphertext = aead.Seal(nil, nonce, privateKeyD.Bytes(), nil)
	return
}

func printPubicKey(publicKey *ecdsa.PublicKey) {
	publicData := PublicData{}
	publicKeyFile, err := os.Create("Signpub.key")
	if err != nil {
		log.Fatal(err)
	}
	defer publicKeyFile.Close()
	publicData.X = publicKey.X
	publicData.Y = publicKey.Y

	marshaledBytes, err := yaml.Marshal(publicData)
	if err != nil {
		return
	}
	_, err = publicKeyFile.WriteString(string(marshaledBytes))
	if err != nil {
		log.Fatal(err)
		return
	}
	return
}

func printPrivateKey(publicKey *ecdsa.PublicKey, nonce []byte, ciphertext []byte, salt []byte) {
	privateData := PrivateData{}
	privateKeyFile, err := os.Create("Signpriv.key")
	if err != nil {
		log.Fatal(err)
		return
	}
	defer privateKeyFile.Close()
	scratchD := big.Int{}
	scratchN := big.Int{}
	scratchS := big.Int{}
	scratchD.SetBytes(ciphertext)
	privateData.D = (&scratchD)
	scratchN.SetBytes(nonce)
	privateData.N = (&scratchN)
	scratchS.SetBytes(salt)
	privateData.S = (&scratchS)

	//   fmt.Printf("Nonce %d \n", nonce)
	//   fmt.Printf("Cipher %d \n", ciphertext)
	//   fmt.Printf("Salt %d \n", salt)

	privateData.X = publicKey.X
	privateData.Y = publicKey.Y
	marshaledBytes, err := yaml.Marshal(privateData)

	if err != nil {
		return
	}
	//  fmt.Printf("%s\n",string(marshaledBytes))
	_, err = privateKeyFile.WriteString(string(marshaledBytes))
	if err != nil {
		log.Fatal(err)
		return
	}
	return
}
