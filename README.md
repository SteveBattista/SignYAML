# SignYAML
Purpose: <br />In Kubernetes, there are a lot of configuration files and container files. This program allows defenders to check to see if someone has changed files before they go into production. This will prevent accidental changes and also limit attackers.

Recommendation:<br />
Giving the rights to edit/delete key files should be given to a different account than the standard one that generates YAML or container files. Also, if you have a SOC, you can alert on changes to the key files to ensure that these are updated explicitly. While configurations can be changed with anyone with the password to re-sign files, changing the keys should be a limited action

Threat Model:<br />
 An attacker has gotten permission to edit .YAML and container files. The defender wants the ability to ensure the integrity of these files and not allow them to be consumed if they have changed and the signed hashes do not match.
 
Version #1:<br />
Defender:  Lets hash (sha256) the files and check the hash. <br />
Attacker: When re-writing the YAML files re-write the hashes

Version #2:<br />
Defender: We will sign the hashes (Using P256) so that attackers can't rewrite the hashes.<br />
Attacker: Your private key is visible, I'll just use it to sign the changed hashes. You know that the private key is going right into #github

Version #3:<br />
Defender: We will encrypt (scrypt) the private key with a typed in password so you can't change it. Password needed to update YAML.<br />
Attacker: Ok, I'll sign YAML with my own private key and change the public key to match so that your verification function will pass.

Version #4<br />
Defender: Signing the pubic key or confirming that public/private keys match would be too burdensome as one would have to type in the password to verify reading any YAML file.<br />

Version #5<br />
Defender: Since the key files don't change often, this should be done with an account that does little else. Also, alerting on the changing of the keys is crucial if you have a SOC overseeing development.<br />
Attacker: I will need to breech the limited account and/or blind the SOC in some way (one way to do this is to force a lot of other alerts).

How to Use<br />
go run CreateKeys.go -> Creates Pubic and Private keys. Encrypts the private key with a typed in password (recommend 10 char random passphrase), Uses P-256 for signing/verifying, chacha20poly1305 for encryption/decryption and scrypt to turn the passphrase into a key. It would be useful to write this down and keep password under control to those that could edit files.

go run SignHash.go <files> -> Creates a file named <filename>.sig. Adds a hash and signs the hash. You will need the passphrase to access the private key created in CreateKeys. The hash is a SHA256 hash of the file.
  
go run CheckHash.go <sigfiles> ->Compares hash in .sig file to the hash of the original file. If these match, it uses the public key to check the signature of the hash. The password is not needed for this function as it does not need to read the private key
 
UpdatedSince.go <seconds> <sigfiles>: Looks for files associated with .sig file and checks to see if they have been updated since certain number of seconds. This will allow users to check for files that have changed since a certain time. This was born out of the fact that large images could take seconds to hash. No reason checking these if they did not change. <br />
  
  Examples:<br />
  CreateKeys.go aruments: None <br />
  `go run CreateKeys.go`<br />
    Enter in PassPhrase to generate key to encrypt private key<br />
    [user types in key it is not echoed back]<br />
    Writing Private key<br />
    Writing Public key<br />

  
  SignHash.go aruments: list of files to create signatures <br />
  `go run SignHash.go file.txt *.yaml`<br />
    Enter in PassPhrase to generate key to decrypt private key<br />
    [user types in key it is not echoed back]<br />
    Creating signing file for file.txt<br />
    Creating signing file for memory-request-limit-3.yaml<br />
    Creating signing file for pod.yaml<br />

 
  CheckHash.go arguments: list of files to create signatures <br />
  `go run CheckHash.go *.sig`<br />
    file.txt :Hash = match  Signature = valid <br />
    memory-request-limit-3.yaml :Hash = match  Signature = valid <br />
    pod.yaml :Hash = match  Signature = valid <br />
    
 
  UpdatedSince.go arguments: number of seconds list of .sig files<br />
  `UpdatedSince.go 1000 *.sig`<br />
  file.txt.sig pod.yaml.sig<br />
  
 UpdatedSince.go example use: ```go run CheckHash.go `go run UpdatedSince.go 1000 *.sig` ```<br />
 file.txt :Hash = match  Signature = valid 
 pod.yaml :Hash = match  Signature = valid 
 
  
  
  Drawbacks:<br />
  On my old laptop Dell Latitude 6400 8Gbram running Ubuntu it took 12 seconds to hash a 2.5GB file. I could see that it could take some time to sign or check a bunch of images.<br />
  I wanted to use the curve25519 and could have used the box library. The issue is that when the check fails, the program stops. I did not want to stop the process as I wanted to be able to check a bunch of files and have the user come back and look at those that did not fail later.<br />
  For the password, I would have really liked to have it printed while typing and then erased when the return is pressed. This would both give feedback to the user and not have the password in the history buffer of the terminal. I don't know if this is possible.<br />
