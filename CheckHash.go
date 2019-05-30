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
  "math/big"
)

type PublicData struct {
   X *big.Int `yaml:"Mx"`
   Y *big.Int `yaml:"My"`
}

type SignedHash struct {
  Hash string `yaml:"Hash"`
  R *big.Int `yaml:"R"`
  S *big.Int `yaml:"S"`
}

func main() {

   publicKey := ecdsa.PublicKey{}
   signedHash :=SignedHash{}
   readPubicKey("Signpub.sig",&publicKey)
// For all arguments
   argslice := os.Args [1:]
   for _,file := range argslice {
//      fmt.Printf("%s : \n",file)
//strip .sig
      filePath := strings.TrimRight(file,".sig") 
//      fmt.Printf("Looking at %s : ",filePath)
// calc sha256 of file
      hashofFile := sha256string(filePath)
 //       fmt.Printf("%s\n",hashofFile)
 //       fmt.Printf("Reading public key\n")
 
      readSignedHash(file,&signedHash)
         // compare to sig's sha256
      hashMatch:= (signedHash.Hash == hashofFile)
      if !(hashMatch){
          fmt.Printf("Hash in sig file does not match hash of file!!!!!\n")
      } else {
// Verify signature of hash with publc key
          fmt.Printf("Hash in sig file matches hash of file.\n")
          valid := ecdsa.Verify(&publicKey, []byte(hashofFile),signedHash.R,signedHash.S)
// if no varification mention
// else mention that it is ok.
           if !(valid) {
              fmt.Printf("Signature of hash is not valid!!!!!\n")
           } else {
             fmt.Printf("Signature of hash is valid.\n")
           }
       }
   }
 
}


func readPubicKey(publicKeyFile string, publicKey *ecdsa.PublicKey) { 
  publicData := PublicData{}
   stream, err := ioutil.ReadFile(publicKeyFile)
   if err != nil {
      log.Fatal(err)
   }    
   err = yaml.Unmarshal(stream, &publicData)
   if err != nil {
      log.Fatal(err)
   }
    publicKey.X = publicData.X
    publicKey.Y = publicData.Y

    publicKey.Curve = elliptic.P256()
 //   fmt.Printf("Public\nX : %d\nY : %d\n",publicKey.X,publicKey.Y)
   return
}

func readSignedHash(sigFile string, signedHash *SignedHash) { 
   stream, err := ioutil.ReadFile(sigFile)
   if err != nil {
      log.Fatal(err)
   }    
   err = yaml.Unmarshal(stream, &signedHash)
   if err != nil {
      log.Fatal(err)
   }

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

