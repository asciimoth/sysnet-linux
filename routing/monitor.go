//go:build linux

package routing

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	defaultRouteMonitorDebounce = 50 * time.Millisecond
	defaultRouteMonitorRetry    = 250 * time.Millisecond
)

type routeSubscribeFunc func(
	chan<- netlink.RouteUpdate,
	<-chan struct{},
	netlink.RouteSubscribeOptions,
) error

type routeSubscription struct {
	events <-chan netlink.RouteUpdate
	done   chan struct{}
	once   sync.Once
}

func (s *routeSubscription) stop() {
	if s == nil {
		return
	}
	s.once.Do(func() { close(s.done) })
}

func (m *Manager) startRouteMonitor(subscribe routeSubscribeFunc) error {
	done := make(chan struct{})
	subscription, err := subscribeRouteUpdates(subscribe, m.monitorOptions)
	if err != nil {
		return err
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		close(done)
		subscription.stop()
		for range subscription.events {
		}
		return errors.New("routing: manager is closed")
	}
	m.monitorDone = done
	m.monitorSubscribe = subscribe
	m.monitorWait.Add(1)
	m.mu.Unlock()

	go m.monitorRouteUpdates(done, subscription)
	return nil
}

func subscribeRouteUpdates(
	subscribe routeSubscribeFunc,
	options netlink.RouteSubscribeOptions,
) (*routeSubscription, error) {
	events := make(chan netlink.RouteUpdate, 32)
	done := make(chan struct{})
	if err := subscribe(
		events,
		done,
		options,
	); err != nil {
		close(done)
		return nil, err
	}
	return &routeSubscription{events: events, done: done}, nil
}

func (m *Manager) monitorRouteUpdates(
	done <-chan struct{},
	subscription *routeSubscription,
) {
	defer m.monitorWait.Done()
	events := subscription.events

	var timer *time.Timer
	var timerC <-chan time.Time
	pending := false
	resetTimer := func(delay time.Duration) {
		if timer == nil {
			timer = time.NewTimer(delay)
			timerC = timer.C
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(delay)
		timerC = timer.C
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		select {
		case <-done:
			subscription.stop()
			if events != nil {
				for range events {
				}
			}
			return
		case update, ok := <-events:
			if !ok {
				subscription.stop()
				subscription = nil
				events = nil
				if !pending {
					pending = true
					_ = m.beginRouteChange()
				}
				resetTimer(m.monitorRetry)
				continue
			}
			if update.Table != unix.RT_TABLE_MAIN {
				continue
			}
			if !pending {
				pending = true
				if err := m.beginRouteChange(); err != nil {
					resetTimer(m.monitorRetry)
				} else {
					resetTimer(m.monitorDebounce)
				}
			}
		case <-timerC:
			timerC = nil
			if events == nil {
				select {
				case <-done:
					return
				default:
				}
				var err error
				subscription, err = subscribeRouteUpdates(
					m.monitorSubscribe,
					m.monitorOptions,
				)
				if err != nil {
					resetTimer(m.monitorRetry)
					continue
				}
				events = subscription.events
			}
			if pending {
				if err := m.refreshAfterRouteChange(); err != nil {
					resetTimer(m.monitorRetry)
					continue
				}
				pending = false
			}
		}
	}
}

func (m *Manager) beginRouteChange() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.applied == nil ||
		m.applied.Config.Strictness == Strict {
		return nil
	}
	config := m.applied.Config
	for _, family := range familyConstants(config.Families) {
		if err := m.adapter.AddRule(
			transitionGuard(config, family),
		); err != nil {
			return fmt.Errorf("install route-change guard: %w", err)
		}
	}
	return nil
}

func (m *Manager) refreshAfterRouteChange() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.applied == nil ||
		m.applied.Config.Strictness == Strict {
		return nil
	}
	return m.refreshLocked()
}
