// Copyright 2020 Authors of Hubble
// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package observer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/build"
	"github.com/cilium/cilium/pkg/hubble/container"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser"
	parserErrors "github.com/cilium/cilium/pkg/hubble/parser/errors"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"

	"github.com/golang/protobuf/ptypes"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DefaultOptions to include in the server. Other packages may extend this
// in their init() function.
var DefaultOptions []observeroption.Option

// LocalObserverServer is an implementation of the server.Observer interface
// that's meant to be run embedded inside the Cilium process. It ignores all
// the state change events since the state is available locally.
type LocalObserverServer struct {
	// ring buffer that contains the references of all flows
	ring *container.RingBuffer

	// events is the channel used by the writer(s) to send the flow data
	// into the observer server.
	events chan *observerTypes.MonitorEvent

	// stopped is mostly used in unit tests to signalize when the events
	// channel is empty, once it's closed.
	stopped chan struct{}

	log logrus.FieldLogger

	// channel to receive events from observer server.
	eventschan chan *observerpb.GetFlowsResponse

	// payloadParser decodes flowpb.Payload into flowpb.Flow
	payloadParser *parser.Parser

	opts observeroption.Options

	// startTime is the time when this instance was started
	startTime time.Time

	nodeName string
}

// NewLocalServer returns a new local observer server.
func NewLocalServer(
	payloadParser *parser.Parser,
	logger logrus.FieldLogger,
	options ...observeroption.Option,
) (*LocalObserverServer, error) {
	opts := observeroption.Default // start with defaults
	options = append(options, DefaultOptions...)
	for _, opt := range options {
		if err := opt(&opts); err != nil {
			return nil, fmt.Errorf("failed to apply option: %v", err)
		}
	}

	logger.WithFields(logrus.Fields{
		"maxFlows":       opts.MaxFlows,
		"eventQueueSize": opts.MonitorBuffer,
	}).Info("Configuring Hubble server")

	s := &LocalObserverServer{
		log:           logger,
		ring:          container.NewRingBuffer(container.WithCapacity(opts.MaxFlows)),
		events:        make(chan *observerTypes.MonitorEvent, opts.MonitorBuffer),
		stopped:       make(chan struct{}),
		eventschan:    make(chan *observerpb.GetFlowsResponse, 100), // option here?
		payloadParser: payloadParser,
		startTime:     time.Now(),
		opts:          opts,
		nodeName:      nodeTypes.GetName(),
	}

	for _, f := range s.opts.OnServerInit {
		err := f.OnServerInit(s)
		if err != nil {
			s.log.WithError(err).Error("failed in OnServerInit")
			return nil, err
		}
	}

	return s, nil
}

// Start implements GRPCServer.Start.
func (s *LocalObserverServer) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

nextEvent:
	for monitorEvent := range s.GetEventsChannel() {
		for _, f := range s.opts.OnMonitorEvent {
			stop, err := f.OnMonitorEvent(ctx, monitorEvent)
			if err != nil {
				s.log.WithError(err).WithField("event", monitorEvent).Info("failed in OnMonitorEvent")
			}
			if stop {
				continue nextEvent
			}
		}

		ev, err := s.payloadParser.Decode(monitorEvent)
		if err != nil {
			if !errors.Is(err, parserErrors.ErrUnknownEventType) {
				s.log.WithError(err).WithField("event", monitorEvent).Debug("failed to decode payload")
			}
			continue
		}

		if flow, ok := ev.Event.(*flowpb.Flow); ok {
			for _, f := range s.opts.OnDecodedFlow {
				stop, err := f.OnDecodedFlow(ctx, flow)
				if err != nil {
					s.log.WithError(err).WithField("event", monitorEvent).Info("failed in OnDecodedFlow")
				}
				if stop {
					continue nextEvent
				}
			}

			// FIXME: Convert metrics into an OnDecodedFlow function
			metrics.ProcessFlow(flow)
		}

		s.GetRingBuffer().Write(ev)
	}
	close(s.GetStopped())
}

// GetEventsChannel returns the event channel to receive flowpb.Payload events.
func (s *LocalObserverServer) GetEventsChannel() chan *observerTypes.MonitorEvent {
	return s.events
}

// GetRingBuffer implements GRPCServer.GetRingBuffer.
func (s *LocalObserverServer) GetRingBuffer() *container.RingBuffer {
	return s.ring
}

// GetLogger implements GRPCServer.GetLogger.
func (s *LocalObserverServer) GetLogger() logrus.FieldLogger {
	return s.log
}

// GetStopped implements GRPCServer.GetStopped.
func (s *LocalObserverServer) GetStopped() chan struct{} {
	return s.stopped
}

// GetPayloadParser implements GRPCServer.GetPayloadParser.
func (s *LocalObserverServer) GetPayloadParser() *parser.Parser {
	return s.payloadParser
}

// GetOptions implements serveroptions.Server.GetOptions.
func (s *LocalObserverServer) GetOptions() observeroption.Options {
	return s.opts
}

// ServerStatus should have a comment, apparently. It returns the server status.
func (s *LocalObserverServer) ServerStatus(
	ctx context.Context, req *observerpb.ServerStatusRequest,
) (*observerpb.ServerStatusResponse, error) {
	status := s.ring.Status()
	return &observerpb.ServerStatusResponse{
		Version:   build.ServerVersion.String(),
		MaxFlows:  uint64(s.opts.MaxFlows),
		NumFlows:  uint64(status.NumEvents),
		SeenFlows: uint64(status.SeenEvents),
		UptimeNs:  uint64(time.Since(s.startTime).Nanoseconds()),
	}, nil
}

// GetNodes implements observerpb.ObserverClient.GetNodes.
func (s *LocalObserverServer) GetNodes(ctx context.Context, req *observerpb.GetNodesRequest) (*observerpb.GetNodesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "GetNodes not implemented")
}

// GetFlows implements the proto method for client requests.
func (s *LocalObserverServer) GetFlows(
	req *observerpb.GetFlowsRequest,
	server observerpb.Observer_GetFlowsServer,
) (err error) {
	// This context is used for goroutines spawned specifically to serve this
	// request, meaning it must be cancelled once the request is done and this
	// function returns.
	ctx, cancel := context.WithCancel(server.Context())
	defer cancel()

	for _, f := range s.opts.OnGetFlows {
		ctx, err = f.OnGetFlows(ctx, req)
		if err != nil {
			return err
		}
	}

	filterList := append(filters.DefaultFilters, s.opts.OnBuildFilter...)
	includeList, err := filters.BuildFilterList(ctx, req.Whitelist, filterList)
	if err != nil {
		return err
	}
	excludeList, err := filters.BuildFilterList(ctx, req.Blacklist, filterList)
	if err != nil {
		return err
	}

	start := time.Now()
	log := s.GetLogger()

	flowsSent := uint64(0)
	defer func() {
		log.WithFields(logrus.Fields{
			"number_of_flows": flowsSent,
			"buffer_size":     s.opts.MaxFlows,
			"include_list":    logFilters(req.Whitelist),
			"exclude_list":    logFilters(req.Blacklist),
			"took":            time.Since(start),
		}).Debug("GetFlows finished")
	}()

	var since time.Time
	if req.Since != nil {
		since, err = ptypes.Timestamp(req.Since)
		if err != nil {
			return err
		}
	}

	var until time.Time
	if req.Until != nil {
		until, err = ptypes.Timestamp(req.Until)
		if err != nil {
			return err
		}
	}

	var ch <-chan *v1.Event
	var cancelRead container.ReaderCancelFunc
	if !since.IsZero() {
		ch, cancelRead = s.ring.ReadSince(since, 0)
	} else if req.Follow {
		ch, cancelRead = s.ring.ReadAll(0)
	} else {
		ch, cancelRead = s.ring.ReadCurrent(0)
	}
	defer cancelRead()

nextFlow:
	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-ch:
			if !ok {
				return nil
			}

			if !until.IsZero() {
				ts, err := ptypes.Timestamp(event.GetFlow().GetTime())
				if err != nil {
					return err
				}
				if !ts.Before(until) {
					return nil
				}
			}

			var resp *observerpb.GetFlowsResponse
			switch e := event.Event.(type) {
			case *flowpb.Flow:
				if filters.Apply(includeList, excludeList, event) {
					resp = &observerpb.GetFlowsResponse{
						Time:     e.GetTime(),
						NodeName: e.GetNodeName(),
						ResponseTypes: &observerpb.GetFlowsResponse_Flow{
							Flow: e,
						},
					}
				}
			case *flowpb.LostEvent:
				resp = &observerpb.GetFlowsResponse{
					Time:     event.Timestamp,
					NodeName: s.nodeName,
					ResponseTypes: &observerpb.GetFlowsResponse_LostEvents{
						LostEvents: e,
					},
				}
			case *flowpb.AgentEvent:
				resp = &observerpb.GetFlowsResponse{
					Time:     event.Timestamp,
					NodeName: s.nodeName,
					ResponseTypes: &observerpb.GetFlowsResponse_AgentEvent{
						AgentEvent: e,
					},
				}
			}

			if resp == nil {
				continue
			}

			for _, f := range s.opts.OnFlowDelivery {
				stop, err := f.OnFlowDelivery(ctx, resp.GetFlow())
				if err != nil {
					return err
				}
				if stop {
					continue nextFlow
				}
			}

			if err := server.Send(resp); err != nil {
				return err
			}

			if resp.GetFlow() != nil {
				flowsSent++
				if req.Number != 0 && flowsSent >= req.Number {
					return nil
				}
			}
		}
	}
}

func logFilters(filters []*flowpb.FlowFilter) string {
	s := make([]string, 0, len(filters))
	for _, f := range filters {
		s = append(s, f.String())
	}
	return "{" + strings.Join(s, ",") + "}"
}
