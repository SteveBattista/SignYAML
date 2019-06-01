package main

import (

	"bytes"
	"crypto/rand"
	"fmt"
	"io"
        "syscall"
        "golang.org/x/crypto/scrypt"
        "golang.org/x/crypto/ssh/terminal"
	"golang.org/x/crypto/chacha20poly1305"
	
)

func main() {

        plaintext := []byte("78159950614993106102261826315902145377927365593578895476104631918663527422869")
        
        
        keyLen := 32
        /*https://www.ietf.org/rfc/rfc2898.txt states that this should be at least 8 octets long. The goal is to prevent re-use
        since 256 is the new hotness (2018-2019) why not make a salt that is 256 bits. It is impossilbe (not enough energy in the universe) to create rainbow tables for 2^256
        salts. */
        salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic(err.Error())
	}
        /* See https://blog.filippo.io/the-scrypt-parameters/ for N value
        The combonation of the salt and the N value is overkill for reversing.
        I also wanted to make this fast so that the check can be done per reading of a YAML file to reduce TOCTOU race conditions
        The decrypted key could still be in memory to speed things up. Hopefully the pass-phrase would be kept in memory, you don't want to have to type the passowrd 100 times. 
        */
	
        fmt.Println("Enter in PassPhrase?")
      
        passPhrasebyte, err := terminal.ReadPassword(int(syscall.Stdin))
        if err != nil {
		panic(err.Error())
	}
        key,err := scrypt.Key(passPhrasebyte, salt, 32768, 8, 1, keyLen)
	if err != nil {
		panic(err.Error())
	}
        fmt.Printf("Input: %s\n",plaintext )
        fmt.Printf("Passphrase: %s\n", string(passPhrasebyte))
        fmt.Printf("Key: %0x\n", key)
        fmt.Printf("Salt: %0x\n", salt)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err.Error())
	}

	// Never use more than 2^32 random nonces with the same key because of the risk of a repeat. https://tools.ietf.org/html/rfc7539 requires a 96 bit nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	fmt.Printf("cipertext: %x\n", ciphertext)
	// For testing incorrect key
	/*if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic(err.Error())
	}
	key,err = scrypt.Key(passPhrasebyte, salt, 32768, 8, 1, keyLen)
	if err != nil {
		panic(err.Error())
	}
	aead, err = chacha20poly1305.New(key)
	if err != nil {
		panic(err.Error())
	}
*/
        decodedplaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("Output : %s\n", decodedplaintext)
 	if (bytes.Equal(decodedplaintext,plaintext)){
		fmt.Printf("Input matches output.\n")
	} else {
		// You should never get here as if the input did not match the output the encryption fuction should fail
		fmt.Printf("Input does not match output!!!!\n")
	}
	
}
