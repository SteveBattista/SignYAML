package main
//Stephen Battista 
//from: https://stackoverflow.com/questions/15879136/how-to-calculate-sha256-file-checksum-in-go
// Looks like the %x in the sprintf will also print out the leading 0s


import (
  "crypto/sha256"
  "fmt"
  "io"
  "log"
  "os"
  "strings"
)

func main() {

// take list of ile paths and generate SHA256 hashes for each of the files
  
   var  hashstring string

   argslice := os.Args [1:]
   for _,files := range argslice {
//    fmt.Printf("%s : ",files)
// Don't hash files ending in .sig
      if (!(endsinsig(files))) {
          hashstring = sha256string(files)
          Writetofile(files, hashstring)
 //         fmt.Printf("%s\n",hashstring)
      }
   }
 
}

func Writetofile(filename string, hashstring string) {
    Sigfile := fmt.Sprintf("%s.%s",filename,"sig")
    fileout, err := os.Create(Sigfile)
    defer fileout.Close()
    if err != nil {
        log.Fatal(err)
	return
     }
    Writestring := fmt.Sprintf("%s : %s\n",filename,hashstring)
    _, err = fileout.WriteString(Writestring)
    if err != nil {
        log.Fatal(err)
	return
     }
//    fmt.Printf("wrote %d bytes to %s\n", writtenbytes,Sigfile)

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

