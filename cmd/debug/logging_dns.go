// nolint
package main

import (
	"fmt"
	"strings"
	"sync"

	gdns "github.com/asciimoth/gonnect/dns"
)

type loggingDNS struct {
	upstream gdns.Interface
	ch       chan gdns.Request
	done     chan struct{}
	once     sync.Once
	wg       sync.WaitGroup
}

func newLoggingDNS(upstream gdns.Interface) *loggingDNS {
	l := &loggingDNS{
		upstream: upstream,
		ch:       make(chan gdns.Request),
		done:     make(chan struct{}),
	}
	l.wg.Add(1)
	go l.run()
	return l
}

func (l *loggingDNS) Requests() chan<- gdns.Request { return l.ch }

func (l *loggingDNS) Close() error {
	l.once.Do(func() { close(l.done) })
	l.wg.Wait()
	return nil
}

func (l *loggingDNS) run() {
	defer l.wg.Done()
	for {
		select {
		case <-l.done:
			return
		case req := <-l.ch:
			l.wg.Add(1)
			go func() {
				defer l.wg.Done()
				l.proxy(req)
			}()
		}
	}
}

func (l *loggingDNS) proxy(req gdns.Request) {
	fmt.Printf(
		"dns request id=%d questions=%s\n",
		req.Message.ID,
		questions(req.Message),
	)

	reply := make(chan gdns.Response, 1)
	select {
	case l.upstream.Requests() <- gdns.Request{
		Context: req.Context,
		Message: req.Message,
		Reply:   reply,
	}:
	case <-req.Context.Done():
		l.reply(req, gdns.Response{Err: req.Context.Err()})
		return
	case <-l.done:
		l.reply(req, gdns.Response{Err: gdns.ErrClosed})
		return
	}

	select {
	case resp := <-reply:
		if resp.Err != nil {
			fmt.Printf("dns response id=%d err=%v\n", req.Message.ID, resp.Err)
		} else if resp.Message != nil {
			fmt.Printf(
				"dns response id=%d rcode=%d answers=%d\n",
				req.Message.ID,
				resp.Message.RCode,
				len(resp.Message.Answers),
			)
		}
		l.reply(req, resp)
	case <-req.Context.Done():
		l.reply(req, gdns.Response{Err: req.Context.Err()})
	case <-l.done:
		l.reply(req, gdns.Response{Err: gdns.ErrClosed})
	}
}

func (l *loggingDNS) reply(req gdns.Request, resp gdns.Response) {
	select {
	case req.Reply <- resp:
	case <-req.Context.Done():
	case <-l.done:
	}
}

func questions(msg *gdns.Message) string {
	if msg == nil || len(msg.Questions) == 0 {
		return "<none>"
	}
	out := make([]string, 0, len(msg.Questions))
	for _, q := range msg.Questions {
		out = append(out, fmt.Sprintf("%s/%d/%d", q.Name, q.Type, q.Class))
	}
	return strings.Join(out, ",")
}
