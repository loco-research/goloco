package loco

import (
	"encoding/binary"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
)

type Frame struct {
	Header struct {
		Method     string
		PacketId   uint32
		StatusCode uint16
		BodyType   uint8
		BodyLength uint32
	}
	Body any
}

func (f *Frame) serializeHeader() []byte {
	var header []byte

	for i := 0; i < 11; i++ {
		if len(f.Header.Method) > i {
			header = append(header, f.Header.Method[i])
		} else {
			header = append(header, 0)
		}
	}
	header = append(header, toByteArray(f.Header.PacketId)...)
	header = append(header, toByteArray(f.Header.StatusCode)...)

	header = append(header, f.Header.BodyType)
	header = append(header, toByteArray(f.Header.BodyLength)...)

	return header
}

func (f *Frame) deserializeHeader(header []byte) (deserializeError error) {
	if len(header) < 22 {
		return fmt.Errorf("[Frame.deserializeHeader] cannot deserialize header: too short")
	}
	f.Header.Method = string(header[0:11])
	f.Header.PacketId = binary.LittleEndian.Uint32(header[11:15])
	f.Header.StatusCode = binary.LittleEndian.Uint16(header[15:17])
	f.Header.BodyType = header[17]
	f.Header.BodyLength = binary.LittleEndian.Uint32(header[18:22])
	return nil
}

func (f *Frame) Serialize() ([]byte, error) {
	var frame []byte
	bsonBody, err := bson.Marshal(f.Body)
	if err != nil {
		return nil, fmt.Errorf("[Frame.Serialize] cannot marshal body : %w", err)
	}
	frame = append(frame, f.serializeHeader()...)
	frame = append(frame, bsonBody...)
	return frame, nil
}

func (f *Frame) Deserialize(decryptedFrame []byte) error {
	if len(decryptedFrame) < 23 {
		return fmt.Errorf("[Frame.Deserialize] cannot deserialize frame: too short")
	}
	if err := f.deserializeHeader(decryptedFrame[0:22]); err != nil {
		return fmt.Errorf("[Frame.Deserialize] cannot deserialize header: %w", err)
	}
	f.Body = bson.M{}
	if err := bson.Unmarshal(decryptedFrame[22:], &f.Body); err != nil {
		return fmt.Errorf("[Frame.Deserialize] cannot unmarshal body: %w", err)
	}
	return nil
}
