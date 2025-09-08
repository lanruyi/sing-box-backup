//go:build linux && go1.25 && !without_badtls

package ktls

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/sagernet/sing-box/common/badtls"
	// C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type Conn struct {
	aTLS.Conn
	ctx             context.Context
	logger          logger.ContextLogger
	conn            net.Conn
	rawConn         *badtls.RawConn
	syscallConn     syscall.Conn
	rawSyscallConn  syscall.RawConn
	readWaitOptions N.ReadWaitOptions
	kernelTx        bool
	kernelRx        bool
	kernelDidRead   bool
	kernelDidWrite  bool
}

func NewConn(ctx context.Context, logger logger.ContextLogger, conn aTLS.Conn, txOffload, rxOffload bool) (aTLS.Conn, error) {
	err := Load()
	if err != nil {
		return nil, err
	}
	syscallConn, isSyscallConn := N.CastReader[interface {
		io.Reader
		syscall.Conn
	}](conn.NetConn())
	if !isSyscallConn {
		return nil, os.ErrInvalid
	}
	rawSyscallConn, err := syscallConn.SyscallConn()
	if err != nil {
		return nil, err
	}
	rawConn, err := badtls.NewRawConn(conn)
	if err != nil {
		return nil, err
	}
	if *rawConn.Vers != tls.VersionTLS13 {
		return nil, os.ErrInvalid
	}
	for rawConn.RawInput.Len() > 0 {
		err = rawConn.ReadRecord()
		if err != nil {
			return nil, err
		}
		for rawConn.Hand.Len() > 0 {
			err = rawConn.HandlePostHandshakeMessage()
			if err != nil {
				return nil, E.Cause(err, "ktls: failed to handle post-handshake messages")
			}
		}
	}
	kConn := &Conn{
		Conn:           conn,
		ctx:            ctx,
		logger:         logger,
		conn:           conn.NetConn(),
		rawConn:        rawConn,
		syscallConn:    syscallConn,
		rawSyscallConn: rawSyscallConn,
	}
	err = kConn.setupKernel(txOffload, rxOffload)
	if err != nil {
		return nil, err
	}
	return kConn, nil
}

func (c *Conn) Upstream() any {
	return c.conn
}

func (c *Conn) ReaderReplaceable() bool {
	if !c.kernelRx {
		return true
	}
	c.rawConn.In.Lock()
	defer c.rawConn.In.Unlock()
	return !c.kernelDidRead
}

func (c *Conn) WriterReplaceable() bool {
	if !c.kernelTx {
		return true
	}
	/*c.rawConn.Out.Lock()
	defer c.rawConn.Out.Unlock()
	return !c.kernelDidWrite*/
	return true
}

func (c *Conn) SyscallConnForRead() syscall.Conn {
	if !c.kernelRx {
		return nil
	}
	c.rawConn.In.Lock()
	defer c.rawConn.In.Unlock()
	if c.kernelDidRead {
		c.logger.DebugContext(c.ctx, "ktls: RX splice not possible, since did read from user space")
		return nil
	}
	c.logger.DebugContext(c.ctx, "ktls: RX splice requested")
	return c.syscallConn
}

func (c *Conn) SyscallConnForWrite() syscall.Conn {
	if !c.kernelTx {
		return nil
	}
	/*c.rawConn.Out.Lock()
	defer c.rawConn.Out.Unlock()
	if c.kernelDidWrite {
		c.logger.DebugContext(c.ctx, "ktls: TX splice not possible, since did write from user space")
		return nil
	}
	*/
	c.logger.DebugContext(c.ctx, "ktls: TX splice requested")
	return c.syscallConn
}
