package loco

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
)

type Session struct {
	PacketId         uint32
	Connection       net.Conn
	Crypto           FrameCryptoInterface
	Logger           *log.Logger
	Handler          map[string][]func(*Frame) error
	responseReceiver map[uint32]chan *Frame
}

func (s *Session) ConnectSocket(host string, port int) error {
	var err error
	s.PacketId = 0
	s.Connection, err = net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return fmt.Errorf("[loco.Session.Connect] failed to connect to %s:%d: %w", host, port, err)
	}
	return nil
}

func (s *Session) DisconnectSocket() error {
	err := s.Connection.Close()
	if err != nil {
		return fmt.Errorf("[loco.Session.Disconnect] failed to close connection: %w", err)
	}
	return nil
}

func (s *Session) Send(frame *Frame) (chan *Frame, error) {
	s.PacketId++
	frame.Header.PacketId = s.PacketId
	plainFrame, err := frame.Serialize()
	if err != nil {
		return nil, fmt.Errorf("[loco.Session.Send] failed to serialize frame: %w", err)
	}
	encryptedFrame, err := s.Crypto.Encrypt(plainFrame)
	if err != nil {
		return nil, fmt.Errorf("[loco.Session.Send] failed to encrypt frame: %w", err)
	}
	_, err = s.Connection.Write(encryptedFrame)
	if err != nil {
		return nil, fmt.Errorf("[loco.Session.Send] failed to write frame: %w", err)
	}
	s.responseReceiver[s.PacketId] = make(chan *Frame, 1)
	return s.responseReceiver[s.PacketId], nil
}

func (s *Session) Receive() error {
	for {
		frame := &Frame{}
		frameSize := make([]byte, 4)
		read, err := s.Connection.Read(frameSize)
		if err != nil {
			s.Logger.Print(fmt.Sprintf("[Receiver] failed to read frame size: %s", err))
			continue
		}
		if read != 4 {
			s.Logger.Print("[Receiver] failed to read frame size")
			continue
		}
		encryptedFrame := make([]byte, binary.LittleEndian.Uint32(frameSize))
		read, err = s.Connection.Read(encryptedFrame)
		if err != nil {
			s.Logger.Print(fmt.Sprintf("[Receiver] failed to read frame: %s", err))
			continue
		}
		if read != len(encryptedFrame) {
			s.Logger.Print("[Receiver] failed to read frame")
			continue
		}
		decryptedFrame, err := s.Crypto.Decrypt(encryptedFrame)
		if err != nil {
			s.Logger.Print(fmt.Sprintf("[Receiver] failed to decrypt frame: %s", err))
			continue
		}
		err = frame.Deserialize(decryptedFrame)
		if err != nil {
			s.Logger.Print(fmt.Sprintf("[Receiver] failed to deserialize frame: %s", err))
			continue
		}
		c, ok := s.responseReceiver[frame.Header.PacketId]
		if ok {
			c <- frame
			continue
		}
		// TODO: handle response receiver
		handlerArr, ok := s.Handler[frame.Header.Method]
		if ok {
			for _, handler := range handlerArr {
				err = handler(frame)
				if err != nil {
					s.Logger.Print(fmt.Sprintf("[Receiver] failed to handle frame: %s", err))
				}
			}
		}
		handlerArr, ok = s.Handler["*"]
		if ok {
			for _, handler := range handlerArr {
				err = handler(frame)
				if err != nil {
					s.Logger.Print(fmt.Sprintf("[Receiver] failed to handle frame: %s", err))
				}
			}
		}
	}
}
