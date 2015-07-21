// Package gocertsigner is a cgo layer that uses libcrypto to produce pkcs7 signatures for golang.
package gocertsigner

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
	"fmt"
	"unsafe"
)

//KeysAndCerts is a struct to store all openssl types and passwords used for signing.
type KeysAndCerts struct {
	password []byte      //password for the p12 cert
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
func (kc *KeysAndCerts) free() {
	kc.clearPassword()
	C.X509PopFree(kc.ca)
	C.X509_free(kc.scert)
	C.EVP_PKEY_free(kc.skey)
}

//clearPassword writes over the memory where the password was stored.
func (kc *KeysAndCerts) clearPassword() {
	for i := 0; i < len(kc.password); i++ {
		kc.password[i] = 0
	}
}

//parse12 reads the Pkcs12 certificate byte slice and parses it into a
//openssl *C.X509 certificate type and an openssl *C.EVP_PKEY type.
func (kc *KeysAndCerts) parseP12(p12Bytes []byte) error {

	var p12 *C.PKCS12
	kc.scert = nil
	kc.skey = nil
	p12 = nil
	defer C.PKCS12_free(p12)

	p12BufLen := C.long(len(p12Bytes))
	p12Buf := ((*C.uchar)(unsafe.Pointer(&p12Bytes[0]))) //go []bytes to C * unsigned char

	if C.d2i_PKCS12(&p12, &p12Buf, p12BufLen) == nil {
		return fmt.Errorf("p12 convert error")
	}

	pass := C.CString(string(kc.password))
	defer C.free(unsafe.Pointer(pass))

	if C.PKCS12_parse(p12, pass, &kc.skey, &kc.scert, nil) == 0 { //parse pkcs12 into 3 files

		var cstr [256]C.char
		C.ERR_error_string(C.ERR_peek_error(), &cstr[0])
		errorStr := C.GoString(&cstr[0])
		return fmt.Errorf("%s", errorStr)
	}

	if kc.skey == nil {
		return fmt.Errorf("p12 key is nil")
	}

	if kc.scert == nil {
		return fmt.Errorf("p12 cert is nil")
	}

	return nil

}

//parseX509Cert reads the X509 der formatted certificate byte slice and parses it into a
//openssl *C.X509 type.
func (kc *KeysAndCerts) parseX509Cert(certX509 []byte) error {

	kc.scert = nil
	certBufLen := C.long(len(certX509))
	certBuf := ((*C.uchar)(unsafe.Pointer(&certX509[0]))) //bytes[] to * unsigned char

	//parse X509 for certificate
	if C.d2i_X509(&kc.scert, &certBuf, certBufLen) == nil {
		var cstr [256]C.char
		C.ERR_error_string(C.ERR_peek_error(), &cstr[0]) //get openssl error code
		errorStr := C.GoString(&cstr[0])
		errorStr = "parse Cert Fail:" + errorStr
		return fmt.Errorf("%s", errorStr)
	}
	if kc.scert == nil {
		return fmt.Errorf("X509 cert is nil")
	}

	return nil

}

//parsePrivateKeyPem reads the private key pem byte slice and parses it into a
//openssl *C.EVP_PKEY type.
func (kc *KeysAndCerts) parsePrivateKeyPem(privKeyPem []byte) error {

	kc.skey = nil

	pemBufLen := C.int(len(privKeyPem))
	pemBuf := (unsafe.Pointer(&privKeyPem[0])) //bytes[] to * unsigned char

	//load the data into a BIO buffer
	privKeyBio := C.BIO_new_mem_buf(pemBuf, pemBufLen)
	defer C.BIO_free(privKeyBio)
	if privKeyBio == nil {
		return fmt.Errorf("error making key pem buffer")
	}

	pass := C.CString(string(kc.password))
	defer C.free(unsafe.Pointer(pass))

	if C.PEM_read_bio_PrivateKey(privKeyBio, &kc.skey, nil, unsafe.Pointer(pass)) == nil {
		var cstr [256]C.char
		C.ERR_error_string(C.ERR_peek_error(), &cstr[0]) //get openssl error code
		errorStr := C.GoString(&cstr[0])
		return fmt.Errorf("%s", errorStr)
	}

	return nil

}

//addCA reads the intermediate & CA root certificates and
//adds them to a X509 cert stack.
func (kc *KeysAndCerts) addCA(ca []byte) error {
	/* Read intermediate & CA root certificates */

	var caCert *C.X509
	caCert = nil
	defer C.X509_free(caCert)

	caBufLen := C.long(len(ca))
	caBuf := ((*C.uchar)(unsafe.Pointer(&ca[0]))) //bytes[] to * unsigned char

	if C.d2i_X509(&caCert, &caBuf, caBufLen) == nil {
		return fmt.Errorf("error adding CA to X509 cert stack")
	}

	if caCert == nil {
		return fmt.Errorf("CA Cert is nil")
	}

	//Add the intermediate CA certificate to the signing stack
	if kc.ca == nil {
		kc.ca = C.X509NewNull()
	}
	C.X509Push(kc.ca, caCert)

	return nil

}

//signDoc uses the KeysAndCerts struct to create a pkcs7 signature.
func (kc *KeysAndCerts) signDoc(document []byte) ([]byte, error) {

	flags := C.int(C.PKCS7_DETACHED | C.PKCS7_BINARY)

	documentBufLen := C.int(len(document))
	documentBuf := (unsafe.Pointer(&document[0])) //bytes[] to * unsigned char

	//load the data into a BIO buffer
	doc := C.BIO_new_mem_buf(documentBuf, documentBufLen)
	defer C.BIO_free(doc)
	if doc == nil {
		return nil, fmt.Errorf("error making document buffer")
	}

	//sign the data and create a pkcs7
	p7 := C.PKCS7_sign(kc.scert, kc.skey, kc.ca, doc, flags)
	defer C.PKCS7_free(p7)
	if p7 == nil {
		return nil, fmt.Errorf("p7 signing error")
	}

	//output pkcs7 to []byte
	var buf (*C.uchar)
	defer C.free(unsafe.Pointer(buf))

	len := C.i2d_PKCS7(p7, &buf)
	if len == 0 {
		return nil, fmt.Errorf("error converting pkcs7 to byte buffer")
	}

	return C.GoBytes(unsafe.Pointer(buf), len), nil

}

//SignWithP12 signs a document using a p12 cert producing a pkcs7 signature.
func SignWithP12(doc []byte, pkcs12 []byte, pkcsPass string, caCert []byte) ([]byte, error) {

	var kc KeysAndCerts
	defer kc.free() //free the C allocated memory

	kc.password = []byte(pkcsPass) //set the password to open the encrypted pkcs12 cert

	//add the intermediate CA certificate
	err := kc.addCA(caCert)
	if err != nil {
		return nil, err
	}

	//parse the p12 into various keys and certificates
	err = kc.parseP12(pkcs12)
	if err != nil {
		return nil, err
	}

	//sign the document
	return kc.signDoc(doc)

}

//SignWithX509PEM signs a document using a x509 der formatted certificate with a pem formatted key producing a pkcs7 signature.
func SignWithX509PEM(doc []byte, x509Cert []byte, pemKey []byte, keyPass string, caCert []byte) ([]byte, error) {

	var kc KeysAndCerts
	defer kc.free() //free the C allocated memory

	kc.password = []byte(keyPass) //set the password to open the encrypted pem private key

	//add the intermediate CA certificate
	err := kc.addCA(caCert)
	if err != nil {
		return nil, err
	}

	//parse the x509 Der to get the certificate
	err = kc.parseX509Cert(x509Cert)
	if err != nil {
		return nil, err
	}

	//parse the pem private key
	err = kc.parsePrivateKeyPem(pemKey)
	if err != nil {
		return nil, err
	}

	//sign the document
	return kc.signDoc(doc)

}
