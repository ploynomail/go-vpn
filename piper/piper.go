package piper

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/songgao/water"
	"github.com/wushilin/go-vpn/common"
	"github.com/wushilin/go-vpn/message"
	"github.com/wushilin/go-vpn/stats"
	"github.com/wushilin/go-vpn/transport"
)

type Pipe struct {
	Iface     *water.Interface
	File      *os.File
	Transport transport.Transport
	FailFlag  bool
	Mutex     *sync.Mutex
	Routes    []string
	Stats     *stats.GlobalStats
}

func (v *Pipe) AtomicExecute(target func()) {
	v.Mutex.Lock()
	defer v.Mutex.Unlock()
	target()
}

// ExecuteControlCommand 通过传输层发送控制命令并等待回复。
// 它以原子方式执行命令以确保线程安全。
//
// 参数：
// - cmd：要发送的控制命令。
//
// 返回：
// - message.Command：从传输层收到的回复命令。
// - error：如果发送或接收命令时出现问题，则会出现错误。
func (v *Pipe) ExecuteControlCommand(cmd message.Command) (message.Command, error) {
	var result message.Command
	var rerr error
	v.AtomicExecute(func() {
		log.Printf("Sending command")
		_, err := v.Transport.WriteControlCommand(cmd)
		if err != nil {
			rerr = err
		}

		log.Printf("Reading command")
		reply, err := v.Transport.ReadControlCommand()
		if err != nil {
			log.Printf("Read command err %s", err)
			rerr = err
		} else {

		}
		result = reply
	})
	return result, rerr
}

// ProcessControlCommand 处理通过传输层接收到的控制命令。
// 它读取命令，检查其是否与预期类型匹配，然后使用提供的处理程序函数对其进行处理。
// 如果命令类型与预期类型不匹配，则发送失败响应。
// 如果成功处理命令，则通过传输层发回响应。
//
// 参数：
// - expectedType：要处理的命令的预期类型。
// - handler：以命令为输入并返回响应命令的函数。
//
// 返回：
// - error：如果读取命令时出现问题、命令类型与预期类型不匹配，
// 或者写入响应命令时出现问题，则会出现错误。
func (v *Pipe) ProcessControlCommand(expectedType message.CMD_TYPE, handler func(cmd message.Command) message.Command) error {
	var err error
	v.AtomicExecute(func() {
		var request message.Command
		request, err = v.Transport.ReadControlCommand()
		if err != nil {
			return
		}
		if request.Type != expectedType {
			err = fmt.Errorf("unexpected command type %d <> expected:%d", request.Type, expectedType)
			response := message.FAIL()
			v.Transport.WriteControlCommand(response)
			return
		}
		response := handler(request)
		var written int
		written, err = v.Transport.WriteControlCommand(response)
		if err != nil {
			log.Printf("Reply error %s", err)
			return
		}
		if written > 0 {
			err = nil
		} else {
			err = errors.New("unsuccessful processing of command")
		}
	})
	return err
}
func NewPipe(iface *water.Interface, transport transport.Transport, routes []string, stats *stats.GlobalStats) (*Pipe, error) {
	file, ok := iface.ReadWriteCloser.(*os.File)
	if !ok {
		return nil, fmt.Errorf("water.Interface %v is does not have a valid file descriptor", iface)
	}
	return &Pipe{
		Iface:     iface,
		File:      file,
		Transport: transport,
		FailFlag:  false,
		Mutex:     new(sync.Mutex),
		Routes:    routes,
		Stats:     stats,
	}, nil
}

func (v *Pipe) Fail() {
	v.FailFlag = true
}

func (v *Pipe) Close() error {
	return v.Transport.Close()
}

func (v *Pipe) Failed() bool {
	return v.FailFlag
}

func (v *Pipe) Run(ctx context.Context, is_server bool) error {
	request_func := func() error {
		routes_join := strings.Join(v.Routes, ";")
		log.Printf("Requesting to route [%s]", routes_join)
		my_request, err := message.WrapCommand(message.CMD_SUBNET_UPDATE, []byte(routes_join))
		if err != nil {
			return err
		}
		response, err := v.ExecuteControlCommand(my_request)
		if err != nil {
			return err
		}
		if response.IsFail() {
			log.Printf("Server didn't accept my routes")
			return fmt.Errorf("server didn't accept my routes")
		} else if response.IsOK() {
			log.Printf("Server said OK")
		} else {
			log.Printf("Server said %d", response.Type)
		}
		return nil
	}

	response_func := func() error {
		return v.ProcessControlCommand(message.CMD_SUBNET_UPDATE, func(x message.Command) message.Command {
			log.Printf("Received route request: [%s]", string(x.Data))
			route_string := string(x.Data)
			array := common.ToArray(route_string)
			for _, next := range array {
				if !common.AddRoute(v.Iface.Name(), next) {
					log.Printf("Unable to add route next due to error: %s", next)
					return message.FAIL()
				}
			}
			log.Printf("Saying OK")
			return message.OK()
		})
	}
	if is_server {
		var err1, err2 error
		err1 = request_func()
		err2 = response_func()
		if err1 != nil || err2 != nil {
			return errors.New("routes setup issue")
		}
	} else {
		var err1, err2 error
		err1 = response_func()
		err2 = request_func()
		if err1 != nil || err2 != nil {
			return errors.New("routes setup issue")
		}
	}
	log.Printf("Routes setup complete")
	wg := new(sync.WaitGroup)
	wg.Add(2)
	go v.file_to_transport(ctx, wg)
	go v.transport_to_file(ctx, wg)
	log.Printf("Link UP!")
	wg.Wait()
	return nil
}

// 处理命令并给出答复
// file_to_transport 从文件读取数据并将其写入传输连接。
// 它循环运行，直到上下文被取消或发生错误。
// 该函数记录进程的开始和结束，以及遇到的任何错误。
// 它还更新上传的字节统计信息。
//
// 参数：
// - ctx：控制函数取消的上下文。
// - wg：函数完成时发出信号的等待组。
func (v *Pipe) file_to_transport(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	var tag = "tun dev -> transport"
	log.Printf("%s started\n", tag)
	defer func() {
		log.Printf("%s ended\n", tag)
	}()
	buffer := make([]byte, 4096)
	run := true
	for run {
		select {
		case <-ctx.Done():
			log.Printf("%s Context cancelled\n", tag)
			run = false
		default:
			// nothing
		}
		if !run {
			v.Transport.Close()
			v.Transport.Close()
			v.Transport.Close()
			v.Transport.Close()
			break
		}
		v.File.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		nread, err := v.File.Read(buffer)
		if err != nil {
			if os.IsTimeout(err) {
				if v.Failed() {
					log.Printf("%s Other party may have failed. Breaking\n", tag)
					break
				}
				continue
			}
			log.Printf("%s Error is %s\n", tag, err)
			v.Fail()
			break
		}
		//log.Printf("%s Read %d bytes\n", tag, nread)
		_, err = v.Transport.Write(buffer[:nread])
		if err != nil {
			log.Printf("%s Write Transport error: %s\n", tag, err)
			v.Fail()
			break
		}
		v.Stats.IncreaseUploadedBytes(uint64(nread))
		//log.Printf("%s Written %d bytes\n", tag, nwritten)
	}
}

// transport_to_file 从 Transport 读取数据并将其写入 TUN 接口。
// 它循环运行，直到上下文被取消或发生错误。
// 该函数记录操作的开始和结束，以及遇到的任何错误。
// 它还更新下载的字节统计信息。
//
// 参数：
// - ctx：控制操作取消的上下文。
// - wg：函数完成时发出信号的等待组。
func (v *Pipe) transport_to_file(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	var tag = "transport -> tun dev"

	log.Printf("%s started\n", tag)
	defer func() {
		log.Printf("%s ended\n", tag)
	}()
	buffer := make([]byte, 4096)
	run := true
	for run {
		select {
		case <-ctx.Done():
			log.Printf("%s Context cancelled\n", tag)
			run = false
		default:
			// nothing
		}
		if !run {
			break
		}
		nread, err := v.Transport.Read(buffer)
		if err != nil {
			if os.IsTimeout(err) {
				if v.Failed() {
					log.Printf("%s Other party may have failed. Breaking\n", tag)
					break
				}
				continue
			}
			log.Printf("%s Error is %s\n", tag, err)
			v.Fail()
			break
		}
		//log.Printf("%s Read %d bytes\n", tag, nread)
		_, err = v.Iface.Write(buffer[:nread])
		if err != nil {
			log.Printf("%s Write TUN error: %s %v\n", tag, err, buffer[:nread])
			v.Fail()
			break
		}
		v.Stats.IncreaseDownloadedBytes(uint64(nread))
		//log.Printf("%s Written %d bytes\n", tag, nwritten)
	}
}
