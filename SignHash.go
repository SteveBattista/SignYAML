package main
//Stephen Battista 
//from: https://stackoverflow.com/questions/15879136/how-to-calculate-sha256-file-checksum-in-go
// Looks like the %x in the sprintf will also print out the leading 0s


import (
   "crypto/sha256"
   "crypto/ecdsa"
   "fmt"
   "io"
   "crypto/elliptic"
   "log"
   "io/ioutil"
   "gopkg.in/yaml.v2"
   "os"
   "strings"
   "crypto/rand"
   "math/big"
   "golang.org/x/crypto/scrypt"
   "golang.org/x/crypto/ssh/terminal"
   "golang.org/x/crypto/chacha20poly1305"
   "syscall"
)

type PrivateData struct {
   D *big.Int `yaml:"EncrypotedD"`
   S *big.Int  `yaml:"Salt"`
   N *big.Int  `yaml:"Nonce"` 
   X *big.Int `yaml:"Mx"`
   Y *big.Int `yaml:"My"`
}

type SignedHash struct {
  Hash string `yaml:"Hash"`
  R *big.Int `yaml:"R"`
  S *big.Int `yaml:"S"`
}

func main() {
   saltLen :=32
   nonceLen := 12
   privateKey := ecdsa.PrivateKey{}
   nonce := make([]byte, nonceLen)
   salt := make([]byte, saltLen)
   nonce,salt = readPrivateKey("Signpriv.sig",&privateKey)
//   fmt.Printf("Nonce %d \n", nonce )
//   fmt.Printf("Salt %d \n", salt )
   symetricKey :=createDecryptKey(salt)
   decryptedKey := decryptKey(privateKey.D,nonce,symetricKey)
   privateKey.D = decryptedKey
// take list of file paths and generate SHA256 hashes for each of the files
   var hashstring string
   
   argslice := os.Args [1:]
   for _,files := range argslice {
//    fmt.Printf("%s : ",files)
// Don't hash files ending in .sig
      if (!(endsinsig(files))) {
          hashstring = sha256string(files)
  
 //       fmt.Printf("%s\n",hashstring)
 //        fmt.Printf("Reading Private key\n")
         
         r, s, err := ecdsa.Sign(rand.Reader, &privateKey, []byte(hashstring))
         if err != nil {
		panic(err)
	   }
 //      fmt.Printf("File : %s\nHash : %s\n r ; %d\n s : %d\n",files, hashstring,r,s)
       Writetofile(files, hashstring,r,s)
      }
   }
 
}

func createDecryptKey(salt []byte ) (key []byte) {
   keyLen := 32
   fmt.Println("Enter in PassPhrase to generate key to decrypt private key")
   passPhrasebyte, err := terminal.ReadPassword(int(syscall.Stdin))
   if err != nil {
      log.Fatalln(err.Error())
   }
   key,err = scrypt.Key(passPhrasebyte, salt, 32768, 8, 1, keyLen)
   if err != nil {
      log.Fatalln(err.Error())
   }
   return
}

func decryptKey(encryptedKey *big.Int, nonce []byte,  key []byte) (decryptedD *big.Int){
   aead, err := chacha20poly1305.New(key)
   if err != nil {
     log.Fatalln(err.Error())
   }
 /*
   fmt.Printf("Nonce %d \n", nonce )
   fmt.Printf("Cipher %d \n", encryptedKey.Bytes())
*/
   decodedplaintext, err := aead.Open(nil, nonce, encryptedKey.Bytes(), nil)
	if err != nil {
      log.Fatalln(err.Error())
	}
//   fmt.Printf("Plaintext %d \n", decodedplaintext)
   scratch := big.Int{}
   scratch.SetBytes(decodedplaintext)
   decryptedD = (&scratch)
   return
}


func readPrivateKey(privateKeyFile string, privateKey *ecdsa.PrivateKey) (nonce []byte, salt []byte){ 
  privateData := PrivateData{}
   stream, err := ioutil.ReadFile(privateKeyFile)
   if err != nil {
      log.Fatal(err)
   }    
   err = yaml.Unmarshal(stream, &privateData)
   if err != nil {
      log.Fatal(err)
   }
   nonce = privateData.N.Bytes()
   salt = privateData.S.Bytes()
   privateKey.D = privateData.D
/* 
   fmt.Printf("Nonce %d == %d \n", (nonce), privateData.N.Bytes())
   fmt.Printf("Cipher %d == %d \n", (privateKey.D.Bytes()), privateData.D.Bytes())
   fmt.Printf("Salt %d == %d \n", (salt), privateData.S.Bytes())
*/
   privateKey.PublicKey.X = privateData.X
   privateKey.PublicKey.Y = privateData.Y
   privateKey.PublicKey.Curve = elliptic.P256()
//   fmt.Printf("Private \nD: %d\nX : %d\nY : %d\n",privateKey.D,privateKey.PublicKey.X,privateKey.PublicKey.Y)

   return
}

func Writetofile(filename string, hashstring string,r *big.Int, s *big.Int) {
    signedHash := SignedHash{}
    Sigfile := fmt.Sprintf("%s.%s",filename,"sig")
    fileout, err := os.Create(Sigfile)
    defer fileout.Close()
    if err != nil {
        log.Fatal(err)
	return
     }
    signedHash.Hash = hashstring
    signedHash.R = r
    signedHash.S = s
 //   fmt.Printf("File : %s\nHash : %s\n r ; %d\n s : %d\n",Sigfile, signedHash.hash,signedHash.r, signedHash.s)
    marshaledBytes, err := yaml.Marshal(signedHash)
    if err != nil {
       return 
    }
 //  fmt.Printf("%s\n",marshaledBytes)
    _, err = fileout.WriteString(string(marshaledBytes))
    if err != nil {
        log.Fatal(err)
	return
     }


}



func endsinsig(filename string) (result bool) {
// Code is a bit lazy. Could look for characters after the . rather than the last 4

   last4  := filename[len(filename)-4:]
// print(filename, " ",last4, " ")
   result =  strings.EqualFold(last4, ".sig")
   return

}

func sha256string(filePath string) (result string) {

//Open a File
    file, err := os.Open(filePath)
    if err != nil {
        log.Fatal(err)
	return
    }
    defer file.Close()
// Create hash
    hash := sha256.New()
//load file into hash
    _, err = io.Copy(hash, file)
    if err != nil {
        log.Fatal(err)
	return
    }
// convert hash into string
    result = fmt.Sprintf("%x", hash.Sum(nil))
    return
}

