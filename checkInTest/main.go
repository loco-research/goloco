package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/loco-research/goloco"
	"go.mongodb.org/mongo-driver/bson"
	"io"
	"net"
	"reflect"
)

func toByteArray(value any) []byte {
	var buffer = new(bytes.Buffer)
	if err := binary.Write(buffer, binary.LittleEndian, value); err != nil {
		return nil
	}
	return buffer.Bytes()
}

func checkError(err error) {
	if err != nil {
		panic(err)
	}
}

func getPacketHeader(
	packetID int,
	statusCode int,
	methodName string,
	bodyType byte,
	bodyLength int,
) []byte {
	var byteArray = make([]byte, 0)

	byteArray = append(byteArray, toByteArray(uint32(packetID))...)
	byteArray = append(byteArray, toByteArray(uint16(statusCode))...)

	var methodNameLen = len(methodName)

	for i := 0; i < 11; i++ {
		if methodNameLen > i {
			byteArray = append(byteArray, methodName[i])
		} else {
			byteArray = append(byteArray, 0)
		}
	}

	byteArray = append(byteArray, bodyType)
	byteArray = append(byteArray, toByteArray(uint32(bodyLength))...)

	return byteArray
}

func getHandshakePacket(len int, rsaEncType int, aesEncType int, encryptedAesKey []byte) []byte {
	var byteArray = make([]byte, 0)

	byteArray = append(byteArray, toByteArray(uint32(len))...)
	byteArray = append(byteArray, toByteArray(uint32(rsaEncType))...)
	byteArray = append(byteArray, toByteArray(uint32(aesEncType))...)
	byteArray = append(byteArray, encryptedAesKey...)

	return byteArray
}

func getEncryptedLocoPacket(len int, iv []byte, encrypted []byte) []byte {
	var byteArray = make([]byte, 0)

	byteArray = append(byteArray, toByteArray(uint32(len))...)
	byteArray = append(byteArray, iv...)
	byteArray = append(byteArray, encrypted...)

	return byteArray
}

type BookingReq struct {
	MCCMNC string `bson:"MCCMNC"`
	Model  string `bson:"model"`
	OS     string `bson:"os"`
}

type CheckinReq struct {
	UserId          uint64 `bson:"userId"`
	OS              string `bson:"os"`
	NetworkType     uint16 `bson:"ntype"`
	AppVer          string `bson:"appVer"`
	Language        string `bson:"lang"`
	NetworkOperator string `bson:"MCCMNC"`
}

func performPacket(tempData []byte, currentData *[]byte, currentLen *int) {
	*currentData = append(*currentData, tempData...)

	if len(*currentData) >= 22 && *currentLen < 1 {
		*currentLen = int(binary.LittleEndian.Uint32((*currentData)[18:][:4])) + 22
	}

	if *currentLen > 0 && len(*currentData) >= *currentLen {
		var bodyData = (*currentData)[22:][:(*currentLen - 22)]
		var doc bson.D
		err := bson.Unmarshal(bodyData, &doc)
		checkError(err)

		go onPacket(doc)

		slicedPacket := (*currentData)[*currentLen:]

		*currentData = make([]byte, 0)
		*currentLen = 0

		performPacket(slicedPacket, currentData, currentLen)
	}
}

func TLSReceive(conn *tls.Conn) {
	var currentData = make([]byte, 0)
	var currentLen = 0

	for {
		var tempData = make([]byte, 256)
		c, err := conn.Read(tempData)
		checkError(err)
		tempData = tempData[:c]
		performPacket(tempData, &currentData, &currentLen)
	}
}

func TCPReceive(conn net.Conn, aesKey []byte) {
	var currentData = make([]byte, 0)
	var currentLen = 0

	var currentData2 = make([]byte, 0)
	var currentLen2 = 0

	for {
		var tempData = make([]byte, 256)
		c, err := conn.Read(tempData)
		checkError(err)
		tempData = tempData[:c]

		currentData = append(currentData, tempData...)

		if len(currentData) >= 20 && currentLen < 1 {
			currentLen = int(binary.LittleEndian.Uint32(currentData[:4])) + 4
		}

		if currentLen > 0 && len(currentData) >= currentLen {
			bodyData := currentData[20:][:(currentLen - 20)]
			tempIV := currentData[4:][:16]
			decryptedData := decryptAES(bodyData, aesKey, tempIV)
			go performPacket(decryptedData, &currentData2, &currentLen2)

			currentData = currentData[currentLen:]
			currentLen = 0
		}
	}
}

var msg chan bson.D

func onPacket(doc bson.D) {
	spew.Dump(doc)
	if msg != nil {
		msg <- doc
	}
}

func booking() bson.D {
	locoFrame := loco.Frame{
		Header: loco.FrameHeader{
			Method:     "GETCONF",
			PacketId:   0,
			StatusCode: 0,
			BodyType:   0,
		},
		Body: BookingReq{
			MCCMNC: "999",
			Model:  "",
			OS:     "win32",
		},
	}

	conn, err := tls.Dial("tcp", "booking-loco.kakao.com:443", nil)
	checkError(err)
	serializedFrame, err := locoFrame.Serialize()
	_, err = conn.Write(serializedFrame)
	checkError(err)

	go TLSReceive(conn)

	result := <-msg
	return result
}

func checkin() bson.D {
	frame := loco.Frame{
		Header: loco.FrameHeader{
			Method:     "CHECKIN",
			PacketId:   0,
			StatusCode: 0,
			BodyType:   0,
		}, Body: CheckinReq{1, "win32", 0, "3.4.0", "ko", "999"},
	}
	serializedFrame, err := frame.Serialize()
	checkError(err)
	fmt.Printf("CHECKIN FRAME:%x\n", serializedFrame)
	crypto := loco.FrameCryptoCFB{}

	aesKey := make([]byte, 16)
	_, err = io.ReadFull(rand.Reader, aesKey)
	checkError(err)
	checkError(crypto.Initialize(aesKey))

	iv := make([]byte, 16)
	_, err = io.ReadFull(rand.Reader, iv)
	checkError(err)

	locoPacket, err := crypto.Encrypt(serializedFrame)
	checkError(err)
	fmt.Printf("LOCO PACKET:%x\n", locoPacket)

	pemKey, err := PEMtoPublicKey(`-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA52Y1NVBfNkzCmnggwVwScdUO7enyo/RtnSsr8io+8cQrhXlsi1Msn8yGQv+JW9AZKyetYeYl/BuCFS7liJixwJ1UFkH7J0m8GRGNH4VRuRMJa97WfvVpsMr1cIaFnoCeRwvvaaqw9/ikWFWw/Cq6ieAsO80pRCcAVh1mCytDUmeqykuz6TYwldTaYbpHO8u48d3jvUXveSv5J9t40GiaMdyVRZpx7LY2M0ZsjjbQXRe8ziXtGEq/8Gk0vkV2BnRk/v6uce8k5ERCWGyVHRaRo6FJljYNvaIoBBx2WGJVbb6fXCLlkPFlH/A9tGZ0fxNDuomZWwnF+EDIDsq5R/G8+wIBAw==
-----END PUBLIC KEY-----`)
	checkError(err)

	aesKeyEnc, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pemKey, aesKey, []byte{})
	checkError(err)

	handshake := getHandshakePacket(len(aesKeyEnc), 14, 2, aesKeyEnc)
	conn, err := net.Dial("tcp", "ticket-loco.kakao.com:443")
	checkError(err)

	_, err = conn.Write(handshake)
	checkError(err)
	_, err = conn.Write(locoPacket)
	checkError(err)

	go TCPReceive(conn, aesKey)

	result := <-msg
	return result
}

func PEMtoPublicKey(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("PEM 파싱에 실패했습니다")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break
	}
	return nil, errors.New("키가 RSA 타입이 아닙니다")
}

func encryptAES(plain, key, iv []byte) (encrypted []byte) {
	block, err := aes.NewCipher(key)
	checkError(err)
	encrypted = make([]byte, len(plain))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encrypted, plain)
	return
}

func decryptAES(plain, key, iv []byte) (decrypted []byte) {
	block, err := aes.NewCipher(key)
	checkError(err)
	decrypted = make([]byte, len(plain))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(decrypted, plain)
	return
}

func main() {
	checkinRes := checkin()
	for _, v := range checkinRes {
		fmt.Println(v.Key, v.Value, reflect.TypeOf(v.Value))
	}
	select {}
}
