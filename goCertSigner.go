// Package goCertSigner is a cgo layer that uses libcrypto to produce pkcs7 signatures for golang.
package goCertSigner

/*
#cgo !windows LDFLAGS: -lcrypto
#cgo windows LDFLAGS: /DEV/openssl-1.0.1e/libcrypto.a -lgdi32
#cgo windows CFLAGS: -I /DEV/openssl-1.0.1e/include

 #include <openssl/x509.h>
 #include <openssl/x509v3.h>
 #include <openssl/pkcs12.h>
 #include <openssl/pkcs7.h>
 #include <openssl/pem.h>
 #include <openssl/evp.h>
 #include <openssl/err.h>
 #include <openssl/safestack.h>
 #include <stdio.h>

typedef STACK_OF(X509) STACK;

static STACK_OF(X509)* X509NewNull() {
	return sk_X509_new_null();
}

static void X509Push(STACK_OF(X509) *ca,X509 *cert) {
	sk_X509_push(ca, cert);
}

static void X509PopFree(STACK_OF(X509) *ca) {
	sk_X509_pop_free(ca, X509_free);
}

*/
import "C"

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"unsafe"
)

//KeysAndCerts is a struct to store all openssl types and passwords used for signing.
type KeysAndCerts struct {
	Password string      //password for the p12 cert
	scert    *C.X509     //cert from the p12 cert
	skey     *C.EVP_PKEY //key from the p12 cert
	ca       *C.STACK    //stack of certificate authorities. CA from 2 sources
}

//init is used to setup openssl by adding all ciphers and digests.
func init() {
	C.OpenSSL_add_all_ciphers()
	C.OpenSSL_add_all_digests()

}

//free cleans up all openssl certificate and key allocated memory
func free(kc *KeysAndCerts) {
	C.X509PopFree(kc.ca)
	C.X509_free(kc.scert)
	C.EVP_PKEY_free(kc.skey)
}

//FileToBytes is a convience function for loading a file and returning a slice of bytes.
func FileToBytes(fileName string) []byte {

	//open file
	file, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(file)

	return buf.Bytes()

}

//BytesToFile is a convience function for saving a slice of bytes to a file.
func BytesToFile(fileName string, outBytes []byte) {

	err := ioutil.WriteFile(fileName, outBytes, 0644)
	if err != nil {
		panic(err)
	}

}

//parse12 reads the Pkcs12 certificate byte slice and parses it into a
//openssl *C.X509 certificate type and an openssl *C.EVP_PKEY type.
func parseP12(kc *KeysAndCerts, p12Bytes []byte) {

	var p12 *C.PKCS12
	kc.scert = nil
	kc.skey = nil
	p12 = nil
	defer C.PKCS12_free(p12)

	p12BufLen := C.long(len(p12Bytes))
	p12Buf := ((*C.uchar)(unsafe.Pointer(&p12Bytes[0]))) //go []bytes to C * unsigned char

	if C.d2i_PKCS12(&p12, &p12Buf, p12BufLen) == nil {
		panic("p12 convert error")
	}

	pass := C.CString(kc.Password)
	defer C.free(unsafe.Pointer(pass))

	if C.PKCS12_parse(p12, pass, &kc.skey, &kc.scert, nil) == 0 { //parse pkcs12 into 3 files

		var cstr [256]C.char
		C.ERR_error_string(C.ERR_peek_error(), &cstr[0])
		errorStr := C.GoString(&cstr[0])
		panic(errorStr)
	}

	if kc.skey == nil {
		panic("skey == nil")
	}

	if kc.scert == nil {
		panic("scert == nil")
	}

}

//parseX509Cert reads the X509 der formatted certificate byte slice and parses it into a
//openssl *C.X509 type.
func parseX509Cert(kc *KeysAndCerts, certX509 []byte) {

	kc.scert = nil
	certBufLen := C.long(len(certX509))
	certBuf := ((*C.uchar)(unsafe.Pointer(&certX509[0]))) //bytes[] to * unsigned char

	//parse X509 for certificate
	if C.d2i_X509(&kc.scert, &certBuf, certBufLen) == nil {
		var cstr [256]C.char
		C.ERR_error_string(C.ERR_peek_error(), &cstr[0]) //get openssl error code
		errorStr := C.GoString(&cstr[0])
		errorStr = "parse Cert Fail:" + errorStr
		panic(errorStr)
	}
	if kc.scert == nil {
		panic("kc.scert == nil")
	}

}

//parsePrivateKeyPem reads the private key pem byte slice and parses it into a
//openssl *C.EVP_PKEY type.
func parsePrivateKeyPem(kc *KeysAndCerts, privKeyPem []byte) {

	kc.skey = nil

	pemBufLen := C.int(len(privKeyPem))
	pemBuf := (unsafe.Pointer(&privKeyPem[0])) //bytes[] to * unsigned char

	//load the data into a BIO buffer
	privKeyBio := C.BIO_new_mem_buf(pemBuf, pemBufLen)
	defer C.BIO_free(privKeyBio)
	if privKeyBio == nil {
		panic("new openssl pem bio error")
	}

	pass := C.CString(kc.Password)
	defer C.free(unsafe.Pointer(pass))

	if C.PEM_read_bio_PrivateKey(privKeyBio, &kc.skey, nil, unsafe.Pointer(pass)) == nil {
		var cstr [256]C.char
		C.ERR_error_string(C.ERR_peek_error(), &cstr[0]) //get openssl error code
		errorStr := C.GoString(&cstr[0])
		panic(errorStr)
	}

}

//addCA reads the intermediate & CA root certificates and
//adds them to a X509 cert stack.
func addCA(kc *KeysAndCerts, ca []byte) {
	/* Read intermediate & CA root certificates */

	var caCert *C.X509
	caCert = nil
	defer C.X509_free(caCert)

	caBufLen := C.long(len(ca))
	caBuf := ((*C.uchar)(unsafe.Pointer(&ca[0]))) //bytes[] to * unsigned char

	if C.d2i_X509(&caCert, &caBuf, caBufLen) == nil {
		panic("add CA fail")
	}

	if caCert == nil {
		panic("caCert == nil")
	}

	//Add the intermediate CA certificate to the signing stack
	if kc.ca == nil {
		kc.ca = C.X509NewNull()
	}
	C.X509Push(kc.ca, caCert)

}

//signDoc uses the KeysAndCerts struct to create a pkcs7 signature.
func signDoc(kc *KeysAndCerts, document []byte) []byte {

	flags := C.int(C.PKCS7_DETACHED | C.PKCS7_BINARY)

	documentBufLen := C.int(len(document))
	documentBuf := (unsafe.Pointer(&document[0])) //bytes[] to * unsigned char

	//load the data into a BIO buffer
	doc := C.BIO_new_mem_buf(documentBuf, documentBufLen)
	defer C.BIO_free(doc)
	if doc == nil {
		panic("new openssl bio error")
	}

	//sign the data and create a pkcs7
	p7 := C.PKCS7_sign(kc.scert, kc.skey, kc.ca, doc, flags)
	defer C.PKCS7_free(p7)
	if p7 == nil {
		panic("p7 sign error")
	}

	//output pkcs7 to []byte
	var buf (*C.uchar)
	defer C.free(unsafe.Pointer(buf))

	len := C.i2d_PKCS7(p7, &buf)
	if len == 0 {
		panic("i2d Pkcs7 error")
	}

	return C.GoBytes(unsafe.Pointer(buf), len)

}

//SignWithP12 signs a document using a p12 cert producing a pkcs7 signature.
func SignWithP12(doc []byte, pkcs12 []byte, pkcsPass string, caCert []byte) (signature []byte, err error) {

	//recover from panics and return error messages
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("signer: %v", r)
			}
		}
	}()

	var kc KeysAndCerts
	defer free(&kc) //free the C allocated memory

	kc.Password = pkcsPass //set the password to open the encrypted pkcs12 cert

	addCA(&kc, caCert)            //add the intermediate CA certificate
	parseP12(&kc, pkcs12)         //parse the p12 into various keys and certificates
	return signDoc(&kc, doc), err //sign the document

}

//SignWithX509PEM signs a document using a x509 der formatted certificate with a pem formatted key producing a pkcs7 signature.
func SignWithX509PEM(doc []byte, x509Cert []byte, pemKey []byte, keyPass string, caCert []byte) (signature []byte, err error) {

	//recover from panics and return error messages
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("signer: %v", r)
			}
		}
	}()

	var kc KeysAndCerts
	defer free(&kc) //free the C allocated memory

	kc.Password = keyPass //set the password to open the encrypted pem private key

	addCA(&kc, caCert)              //add the intermediate CA certificate
	parseX509Cert(&kc, x509Cert)    //parse the x509 Der to get the certificate
	parsePrivateKeyPem(&kc, pemKey) //parse the pem private key
	return signDoc(&kc, doc), err   //sign the document

}
