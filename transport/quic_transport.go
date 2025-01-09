package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/wushilin/go-vpn/message"
	"github.com/wushilin/pool"
)

const STREAMS = 30

type QuicConfig struct {
	KeyFile  string
	CertFile string
	CAFile   string
}

type CLOSE_REASON int

const CLOSE CLOSE_REASON = 0
const CONTROL CLOSE_REASON = 1

var REASON_STRING = map[CLOSE_REASON]string{
	CLOSE:   "graceful shutdown",
	CONTROL: "control stream can't be openned",
}

func CloseConn(conn quic.Connection, reason CLOSE_REASON) error {
	reason_s, ok := REASON_STRING[reason]
	if !ok {
		reason_s = "undefined"
	}
	if conn != nil {
		return conn.CloseWithError(quic.ApplicationErrorCode(int(reason)), reason_s)
	} else {
		return nil
	}
}
func (v QuicConfig) GenerateTLSConfig(server_addr string, is_server bool) *tls.Config {
	key_bytes, err := os.ReadFile(v.KeyFile)
	if err != nil {
		log.Fatal(err)
	}

	cert_bytes, err := os.ReadFile(v.CertFile)
	if err != nil {
		log.Fatal(err)
	}

	ca_bytes, err := os.ReadFile(v.CAFile)
	if err != nil {
		log.Fatal(err)
	}

	tlsCert, err := tls.X509KeyPair(cert_bytes, key_bytes)
	if err != nil {
		panic(err)
	}
	cert_pool := x509.NewCertPool()
	block, _ := pem.Decode(ca_bytes)

	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
	cert_pool.AddCert(ca)
	if is_server {
		return &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			ClientAuth:   tls.RequireAndVerifyClientCert, // used by server
			ClientCAs:    cert_pool,                      // used by server
			NextProtos:   []string{"quic"},
		}
	} else {
		if server_addr != "" {
			tokens := strings.Split(server_addr, ":")
			return &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
				RootCAs:      cert_pool, // used by client
				NextProtos:   []string{"quic"},
				ServerName:   tokens[0],
			}
		} else {
			return &tls.Config{
				Certificates:       []tls.Certificate{tlsCert},
				RootCAs:            cert_pool, // used by client
				NextProtos:         []string{"quic"},
				InsecureSkipVerify: true,
			}
		}
	}
}

func ReadCommand(r io.Reader) (message.Command, error) {
	buffer := make([]byte, 4096)
	nread, err := io.ReadFull(r, buffer[:3])
	if err != nil {
		return message.Command{}, err
	}

	size := int(buffer[1])*256 + int(buffer[2])
	nread2, err := io.ReadFull(r, buffer[3:3+size])
	if err != nil {
		return message.Command{}, err
	}
	nread += nread2
	return message.ParseCommand(buffer[:nread])
}

func get_stats[T any](p *pool.Pool[T]) string {
	return fmt.Sprintf("Borrowed: %d Created: %d Returned: %d Destroyed: %d Tested: %d",
		p.BorrowedCount(), p.CreatedCount(), p.ReturnedCount(), p.DestroyedCount(), p.TestedCount())
}
func WriteCommand(w io.Writer, command message.Command) (int, error) {
	nwritten, err := w.Write([]byte{
		byte(command.Type),
		byte(command.Length / 256),
		byte(command.Length % 256),
	})
	if err != nil {
		return nwritten, err
	}
	nwritten2, err := w.Write(command.Data)
	nwritten += nwritten2
	return nwritten, err
}

func DefaultConfig() *quic.Config {
	return &quic.Config{
		KeepAlivePeriod: 3 * time.Second,
		MaxIdleTimeout:  10 * time.Second,
	}
}

// decodePacket 从提供的 QUIC 流中读取并解码数据包。
// 它首先读取前两个字节以确定数据包的大小，
// 然后根据大小读取剩余的字节。该函数返回
// 读取的总字节数以及读取操作期间遇到的任何错误。
//
// 参数：
// - str：要读取的 QUIC 流。
// - buffer：用于存储读取数据的字节切片。
//
// 返回：
// - int：读取的总字节数。
// - error：读取操作期间遇到的任何错误。
func decodePacket(str quic.Stream, buffer []byte) (int, error) {
	nread, err := io.ReadFull(str, buffer[:2])
	if err != nil {
		return nread, err
	}
	size := int(buffer[0])*256 + int(buffer[1])
	dataread, err := io.ReadFull(str, buffer[2:size+2])
	nread += dataread
	if err != nil {
		return nread, err
	}
	return nread, nil
}

func Ping(writer io.Writer) error {
	_, err := writer.Write([]byte{0})
	return err
}

func Pong(reader io.Reader) error {
	buffer := make([]byte, 1)
	_, err := io.ReadFull(reader, buffer)
	return err
}

// runReaders 初始化并管理多个 QUIC 流以读取数据。
//
// 它启动指定数量的读取器流，要么接受传入的
// 流，要么根据“accept”参数打开新的流。每个流
// 读取数据包并将其发送到提供的通道。
//
// 参数：
// - pool：用于缓冲数据的字节切片池。
// - conn：用于接受或打开流的 QUIC 连接。
// - mystreams：要管理的 QUIC 流切片。
// - ch：发送缓冲数据的通道。
// - accept：一个布尔值，指示是否接受传入流（true）
// 或打开新流（false）。
//
// 返回：
// - 如果任何流无法被接受或打开，或者在操作期间发生任何其他
// 错误，则会出现错误。
//
// 该函数记录读取器流的开始和停止，并确保
// 所有流都已正确关闭且通道在返回之前已关闭。
func runReaders(pool *pool.Pool[[]byte], conn quic.Connection, mystreams []quic.Stream, ch chan Buffer, accept bool) error {
	log.Printf("Starting %d reader streams...\n", len(mystreams))
	defer func() {
		log.Printf("Stopped %d reader streams.\n", len(mystreams))
	}()
	for i := 0; i < len(mystreams); i++ {
		var str quic.Stream
		var err error
		if accept {
			str, err = conn.AcceptStream(context.Background())
			if err == nil {
				Pong(str)
			}
		} else {
			str, err = conn.OpenStreamSync(context.Background())
			if err == nil {
				Ping(str)
			}
		}
		if err != nil {
			for j := 0; j < i; j++ {
				mystreams[j].Close()
			}
			return err
		}
		mystreams[i] = str
	}
	wg := new(sync.WaitGroup)
	for i := 0; i < len(mystreams); i++ {
		var id int = i
		var thestream = mystreams[id]
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				buffer, _ := pool.Borrow()
				count, err := decodePacket(thestream, buffer)
				if err != nil {
					// connection broken
					return
				}
				ch <- WrapBuffer(buffer, 2, count)
			}
		}()
	}
	wg.Wait()
	for _, str := range mystreams {
		if str != nil {
			str.Close()
		}
	}
	close(ch)
	return nil
}

// qRead 将数据从通道读取到提供的缓冲区中。
//
// 参数：
// - pool：用于高效内存管理的字节切片池。
// - from：接收 Buffer 对象的通道。
// - buffer：将复制读取数据的字节切片。
//
// 返回：
// - int：复制到缓冲区的字节数。
// - error：如果读取操作失败，则出现错误；如果通道已关闭，则出现 io.EOF。
//
// 可能的错误：
// - io.EOF：如果通道已关闭，并且没有更多可用数据。
// - io.ErrShortBuffer：如果提供的缓冲区太小，无法容纳数据。
func qRead(pool *pool.Pool[[]byte], from chan Buffer, buffer []byte) (int, error) {
	read, ok := <-from
	if !ok {
		return 0, io.EOF
	}

	slice := read.Slice
	start := read.Start
	end := read.End
	length := end - start
	if length > len(buffer) {
		return 0, io.ErrShortBuffer
	}
	copied := copy(buffer, slice[start:end])
	pool.Return(slice)
	return copied, nil
}
