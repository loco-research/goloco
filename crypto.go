package loco

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

type FrameCryptoInterface interface {
	Initialize(key []byte) error
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
	GetType() int
	GetKey() []byte
}

type FrameCryptoCFB struct {
	key   []byte
	block cipher.Block
}

func (f *FrameCryptoCFB) Initialize(key []byte) error {
	f.key = key
	block, err := aes.NewCipher(f.key)
	if err != nil {
		return fmt.Errorf("[FrameCryptoCFB.Initialize] failed to create new AES block : %w", err)
	}
	f.block = block
	return nil
}

func (f *FrameCryptoCFB) Encrypt(plainFrame []byte) (encryptedFrame []byte, cryptoError error) {
	defer func() {
		if r := recover(); r != nil {
			encryptedFrame = nil
			cryptoError = fmt.Errorf("[FrameCryptoCFB.Encrypt] Panic : %s", r)
		}
	}()
	iv := randomByte(f.block.BlockSize())
	encryptedFrame = append(encryptedFrame, toByteArray(uint32(len(plainFrame)+16))...)
	encryptedFrame = append(encryptedFrame, iv...)
	encryptedStream := make([]byte, len(plainFrame)-16)
	cipher.NewCFBEncrypter(f.block, iv).XORKeyStream(encryptedStream, plainFrame)
	encryptedFrame = append(encryptedFrame, encryptedStream...)
	return encryptedFrame, nil
}

func (f *FrameCryptoCFB) Decrypt(encryptedFrame []byte) (decryptedFrame []byte, cryptoError error) {
	defer func() {
		if r := recover(); r != nil {
			decryptedFrame = nil
			cryptoError = fmt.Errorf("[FrameCryptoCBC.Decrypt] Panic : %s", r)
		}
	}()
	decryptedFrame = make([]byte, len(encryptedFrame))
	cipher.NewCFBDecrypter(f.block, encryptedFrame[0:16]).XORKeyStream(decryptedFrame, encryptedFrame[16:])
	return decryptedFrame, nil
}

func (f *FrameCryptoCFB) GetType() int {
	return 2
}

func (f *FrameCryptoCFB) GetKey() []byte {
	return f.key
}

type FrameCryptoCBC struct {
	key   []byte
	block cipher.Block
}

func (f *FrameCryptoCBC) Initialize(key []byte) error {
	f.key = key
	block, err := aes.NewCipher(f.key)
	if err != nil {
		return fmt.Errorf("[FrameCryptoCBC.Initialize] failed to crete new AES block : %w", err)
	}
	f.block = block
	return nil
}

func (f *FrameCryptoCBC) Encrypt(plainFrame []byte) (encryptedFrame []byte, cryptoError error) {
	defer func() {
		if r := recover(); r != nil {
			encryptedFrame = nil
			cryptoError = fmt.Errorf("[FrameCryptoCBC.Encrypt] Panic : %s", r)
		}
	}()
	temp := make([]byte, len(plainFrame))
	iv := randomByte(f.block.BlockSize())
	cipher.NewCBCEncrypter(f.block, iv).CryptBlocks(temp, plainFrame)
	temp, err := pkcs7pad(temp, f.block.BlockSize())
	if err != nil {
		return nil, err
	}
	encryptedFrame = append(encryptedFrame, toByteArray(len(temp)+16)...)
	encryptedFrame = append(encryptedFrame, iv...)
	encryptedFrame = append(encryptedFrame, temp...)
	return encryptedFrame, nil
}

func (f *FrameCryptoCBC) Decrypt(encryptedFrame []byte) (decryptedFrame []byte, cryptoError error) {
	defer func() {
		if r := recover(); r != nil {
			decryptedFrame = nil
			cryptoError = fmt.Errorf("[FrameCryptoCBC.Decrypt] Panic : %s", r)
		}
	}()
	decryptedFrame = make([]byte, len(encryptedFrame)-16)
	cipher.NewCFBDecrypter(f.block, encryptedFrame[0:16]).XORKeyStream(decryptedFrame, encryptedFrame[16:])
	decryptedFrame, err := pkcs7strip(decryptedFrame, f.block.BlockSize())
	if err != nil {
		return nil, err
	}
	return decryptedFrame, nil
}

func (f *FrameCryptoCBC) GetType() int {
	return 3
}

func (f *FrameCryptoCBC) GetKey() []byte {
	return f.key
}
