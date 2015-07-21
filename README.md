    Name    : GoCertSigner Library                      
    Author  : Noah Shibley, http://socialhardware.net                       
    Date    : July 8th 2014                                 
    Version : 0.1                                               
    Notes   : A cgo layer that uses openssl to produce pkcs7 signatures for golang
    Dependencies:   openssl or libressl: libcrypto

***
# Function List:
```go
        //signs a document using a p12 cert producing a pkcs7 signature
        SignWithP12(doc []byte, pkcs12 []byte, pkcsPass string, caCert []byte) (signature []byte, err error) 
        
        //signs a document using a x509 der cert with a pem Key producing a pkcs7 signature
        SignWithX509PEM(doc []byte, x509Cert []byte, pemKey []byte, keyPass string, caCert []byte) (signature []byte, err error)
```
***

# Example:

```go

package main

import (
        s "github.com/slugmobile/gocertsigner"
        "log"
)

func main() {

        //get doc to sign
        doc, err := ioutil.ReadFile("myfile.txt")
        if err != nil {
                log.Printf("error: %s", err)
        }

        //your pkcs12 certificate
        p12, err := ioutil.ReadFile("testCert.p12")
        if err != nil {
                log.Printf("error: %s", err)

        }

        //your certificate authority cert
        caCert, err := ioutil.ReadFile("ca.cer")
        if err != nil {
                log.Printf("error: %s", err)

        }

        //your cert password. Store somewhere safe, not in code.
        p12pass := "yourCertPassword"

        //create the signature
        signature, err := s.SignWithP12(doc, p12, p12pass, caCert)
        if err != nil {
                log.Printf("error: %s", err)
        }

        //write out to disk
        ioutil.WriteFile("Signature", signature, 0644)
        if err != nil {
                log.Printf("error: %s", err)
        }

}
```
