	Name    : GoCertSigner Library                      
	Author  : Noah Shibley, http://socialhardware.net                       
	Date    : July 8th 2014                                 
	Version : 0.1                                               
	Notes   : A cgo layer that uses openssl to produce pkcs7 signatures for golang
	Dependencies:   openssl lib

***
# Function List:

	SignDocument(doc []byte, pkcs12 []byte, pkcsPass string, caCert []byte) (signature []byte, err error) //signs the document producing a pkcs7 signature
	BytesToFile(fileName string, outBytes []byte) //outputs a slice of bytes to a file
	FileToBytes(fileName string) []byte //reads in a file to a slice of bytes

***

# Example:

```
#!go

package main

import (
        s "bitbucket.org/cicadaDev/goCertSigner"
        "log"
)

func main() {

         
        doc := s.FileToBytes("myfile.txt")    //get doc to sign
        p12 := s.FileToBytes("testCert.p12")  //your pkcs12 certificate
        p12pass := "yourCertPassword" 		  //store somewhere safe, not in code. 
        caCert := s.FileToBytes("ca.cer")     //your certificate authority cert

        signature, err := s.SignDocument(doc, p12, p12pass, caCert)
        if err != nil {
                log.Printf("error: %v", err)
        }

        s.BytesToFile("Signature", signature)

}
```