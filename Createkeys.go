package main
import ("fmt"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/rand"
   "log"
   "os"
   "gopkg.in/yaml.v2"
   "math/big"
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
   privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
   if err != nil {
      log.Fatalln(err.Error())
   }
   publicKey := privateKey.Public().(*ecdsa.PublicKey)
   fmt.Printf("Writing Private key\n")
   printPrivateKey(privateKey,publicKey)
 
   
   fmt.Printf("Writing Public key\n")
   printPubicKey(publicKey)

}

func printPubicKey(publicKey *ecdsa.PublicKey){
   publicData := PublicData{}
   publicKeyFile, err := os.Create("Signpub.sig")
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


func printPrivateKey(privateKey *ecdsa.PrivateKey,publicKey *ecdsa.PublicKey) { 
   privateData := PrivateData{}
   
   privateKeyFile, err := os.Create("Signpriv.sig")
   if err != nil {
      log.Fatal(err)
      return
     }
   defer privateKeyFile.Close()
   privateData.D = privateKey.D
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



