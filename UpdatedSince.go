package main

//Stephen Battista
//from: https://stackoverflow.com/questions/15879136/how-to-calculate-sha256-file-checksum-in-go
// Looks like the %x in the sprintf will also print out the leading 0s

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

func main() {
	currentTime := time.Now()
	seconds, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	searchTime := currentTime.Add((-1 * time.Duration(seconds*1000)) * time.Millisecond)
	if err != nil {
		log.Fatal(err)
	}
	argslice := os.Args[2:]
	for _, file := range argslice {
		//strip .sig
		filePath := file[:len(file)-4]
		// fmt.Printf("%s :", filePath)
		file, err := os.Stat(filePath)
		if err != nil {
			log.Fatal(err)
		}
		modifiedTime := file.ModTime()
		if searchTime.Before(modifiedTime) {
			fmt.Printf("%s.sig ", filePath)
		}
	}

}
