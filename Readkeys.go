package main
import ("fmt"
   "math/big"
   "crypto/ecdsa"
   "crypto/elliptic"
   "log"
   "io/ioutil"
   "gopkg.in/yaml.v2"
)

type PrivateData struct {
   D *big.Int `yaml:"D"`
   X *big.Int `yaml:"Mx"`
   Y *big.Int `yaml:"My"`
}

type PublicData struct {
   X *big.Int `yaml:"Mx"`
   Y *big.Int `yaml:"My"`
}


func main() {
   publicKey := ecdsa.PublicKey{}
   fmt.Printf("Reading Public key\n")
   readPubicKey("Signpub.sig",&publicKey)

   privateKey := ecdsa.PrivateKey{}
   fmt.Printf("Reading Private key\n")
   readPrivateKey("Signpriv.sig",&privateKey)
   fmt.Printf("Public\nX : %d\nY : %d\n",publicKey.X,publicKey.Y)
   fmt.Printf("Private \nD: %d\nX : %d\nY : %d\n",privateKey.D,privateKey.PublicKey.X,privateKey.PublicKey.Y)
 
  
  

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
//  fmt.Printf("Public\nX : %d\nY : %d\n",publicKey.X,publicKey.Y)
   return
}


func readPrivateKey(privateKeyFile string, privateKey *ecdsa.PrivateKey) { 
  privateData := PrivateData{}
   stream, err := ioutil.ReadFile(privateKeyFile)
   if err != nil {
      log.Fatal(err)
   }    
   err = yaml.Unmarshal(stream, &privateData)
   if err != nil {
      log.Fatal(err)
   }
   privateKey.D = privateData.D
   privateKey.PublicKey.X = privateData.X
   privateKey.PublicKey.Y = privateData.Y
   privateKey.PublicKey.Curve = elliptic.P256()
//   fmt.Printf("Private \nD: %d\nX : %d\nY : %d\n",privateKey.D,privateKey.PublicKey.X,privateKey.PublicKey.Y)

   return
}


