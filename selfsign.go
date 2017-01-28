package selfsign

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

const (
	KEYBLOCK  = "RSA PRIVATE KEY"
	CERTBLOCK = "CERTIFICATE"
)

var (
	NoSuchBlock = errors.New("No such PEM block")
)

func writePem(filename, blockname string, data []byte, mode os.FileMode) error {
	b := &pem.Block{
		Type:  blockname,
		Bytes: data,
	}
	return ioutil.WriteFile(filename, pem.EncodeToMemory(b), mode)
}

func readPem(filename, blockname string) (*pem.Block, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	for {
		var blk *pem.Block
		blk, content = pem.Decode(content)
		if blk == nil {
			break
		}
		if blk.Type == blockname {
			return blk, nil
		}
	}
	return nil, NoSuchBlock
}

func ReadCertificates(certfile, keyfile string) (cert *x509.Certificate, key *rsa.PrivateKey) {
	certblock, err := readPem(certfile, CERTBLOCK)
	if err != nil {
		return
	}
	keyblock, err := readPem(keyfile, KEYBLOCK)
	if err != nil {
		return
	}

	key, err = x509.ParsePKCS1PrivateKey(keyblock.Bytes)
	if err != nil {
		return
	}

	cert, err = x509.ParseCertificate(certblock.Bytes)
	if err != nil {
		key = nil
		return
	}

	return
}

func GenerateCertificate(hostname, certfile, keyfile string) error {
	cert, key := ReadCertificates(certfile, keyfile)

	if cert != nil {

		certOkay := false

		for _, name := range cert.DNSNames {
			if name == hostname {
				certOkay = true
				break
			}
		}

		if !certOkay {
			cert.DNSNames = append(cert.DNSNames, hostname)
		}

		if cert.NotAfter.Before(time.Now().AddDate(0, 0, -15)) {
			certOkay = false
		}

		if certOkay {
			return nil
		}

		cert.SerialNumber.Add(cert.SerialNumber, big.NewInt(1))
	} else {
		name := pkix.Name{
			CommonName: hostname,
		}
		cert = &x509.Certificate{
			SerialNumber: big.NewInt(1),

			Subject: name,
			Issuer:  name,

			NotBefore: time.Now().AddDate(0, 0, -1),
			NotAfter:  time.Now().AddDate(0, 3, 0),

			SignatureAlgorithm: x509.SHA256WithRSA,

			DNSNames: []string{hostname},

			KeyUsage:    x509.KeyUsageCertSign,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
	}

	var err error

	if key == nil {
		key, err = rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			return err
		}
		keydata := x509.MarshalPKCS1PrivateKey(key)
		err = writePem(keyfile, KEYBLOCK, keydata, 0600)
		if err != nil {
			return err
		}
	}

	certdata, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		return err
	}

	err = writePem(certfile, CERTBLOCK, certdata, 0666)
	if err != nil {
		return err
	}

	return nil
}
