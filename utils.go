package loco

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

func toByteArray(value any) []byte {
	var buffer = new(bytes.Buffer)
	if err := binary.Write(buffer, binary.LittleEndian, value); err != nil {
		return nil
	}
	return buffer.Bytes()
}

func randomByte(n int) []byte {
	var random = make([]byte, n)
	_, _ = rand.Read(random)
	return random
}

// pkcs7strip remove pkcs7 padding
func pkcs7strip(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("[pkcs7strip]: Data is empty")
	}
	if length%blockSize != 0 {
		return nil, errors.New("[pkcs7strip]: Data is not block-aligned")
	}
	padLen := int(data[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(data, ref) {
		return nil, errors.New("[pkcs7strip]: Invalid padding")
	}
	return data[:length-padLen], nil
}

// pkcs7pad add pkcs7 padding
func pkcs7pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize < 0 || blockSize > 256 {
		return nil, fmt.Errorf("[pkcs7pad]: Invalid block size %d", blockSize)
	} else {
		padLen := blockSize - len(data)%blockSize
		padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
		return append(data, padding...), nil
	}
}
