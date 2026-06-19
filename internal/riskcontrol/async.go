package riskcontrol

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

var errAsyncAuditQueueFull = errors.New("risk control async audit queue full")

var defaultAsyncAuditDispatcher = NewAsyncAuditDispatcher()

type asyncCodexAuditTask struct {
	cfg       *config.Config
	settings  settings
	sessionID string
	req       executor.Request
	opts      executor.Options
	input     AuditInput
}

type AsyncAuditDispatcher struct {
	mu        sync.Mutex
	queue     chan asyncCodexAuditTask
	workers   int
	queueSize int
	closed    bool
	jobsWG    sync.WaitGroup
	workerWG  sync.WaitGroup
}

func NewAsyncAuditDispatcher() *AsyncAuditDispatcher {
	return &AsyncAuditDispatcher{}
}

func (d *AsyncAuditDispatcher) Enqueue(task asyncCodexAuditTask) error {
	if d == nil {
		return errAsyncAuditQueueFull
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return errAsyncAuditQueueFull
	}
	d.ensureStartedLocked(task.settings.asyncWorkers, task.settings.asyncQueueSize)
	d.jobsWG.Add(1)
	select {
	case d.queue <- task:
		return nil
	default:
		d.jobsWG.Done()
		return errAsyncAuditQueueFull
	}
}

func (d *AsyncAuditDispatcher) Close() {
	if d == nil {
		return
	}

	d.mu.Lock()
	if d.closed || d.queue == nil {
		d.closed = true
		d.mu.Unlock()
		return
	}
	queue := d.queue
	d.queue = nil
	d.closed = true
	close(queue)
	d.mu.Unlock()

	d.workerWG.Wait()
}

func (d *AsyncAuditDispatcher) WaitIdle(timeout time.Duration) bool {
	if d == nil {
		return true
	}
	done := make(chan struct{})
	go func() {
		d.jobsWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (d *AsyncAuditDispatcher) ensureStartedLocked(workers int, queueSize int) {
	if d.queue != nil {
		return
	}
	if workers <= 0 {
		workers = defaultAsyncWorkers
	}
	if queueSize <= 0 {
		queueSize = defaultAsyncQueueSize
	}
	d.queue = make(chan asyncCodexAuditTask, queueSize)
	d.workers = workers
	d.queueSize = queueSize
	for i := 0; i < workers; i++ {
		d.workerWG.Add(1)
		go func() {
			defer d.workerWG.Done()
			for task := range d.queue {
				processAsyncCodexAuditTask(task)
				d.jobsWG.Done()
			}
		}()
	}
}

func newAsyncCodexAuditTask(cfg *config.Config, settings settings, sessionID string, req executor.Request, opts executor.Options, input AuditInput) asyncCodexAuditTask {
	return asyncCodexAuditTask{
		cfg:       cfg,
		settings:  settings,
		sessionID: sessionID,
		req: executor.Request{
			Model:    req.Model,
			Payload:  append([]byte(nil), req.Payload...),
			Format:   req.Format,
			Metadata: cloneMetadata(req.Metadata),
		},
		opts: executor.Options{
			Stream:          opts.Stream,
			Alt:             opts.Alt,
			Headers:         cloneHeader(opts.Headers),
			OriginalRequest: append([]byte(nil), opts.OriginalRequest...),
			SourceFormat:    opts.SourceFormat,
			Metadata:        cloneMetadata(opts.Metadata),
		},
		input: AuditInput{
			Text:         input.Text,
			Images:       cloneStrings(input.Images),
			MessageCount: input.MessageCount,
			Hash:         input.Hash,
			FocusText:    input.FocusText,
			FocusStatus:  input.FocusStatus,
			FocusReason:  input.FocusReason,
		},
	}
}

func processAsyncCodexAuditTask(task asyncCodexAuditTask) {
	startedAt := time.Now()
	decision := performAudit(context.Background(), task.cfg, task.settings, task.sessionID, task.req.Model, task.input)
	finishedAt := time.Now()
	duration := finishedAt.Sub(startedAt)

	recordCodexAuditLog(startedAt, duration, task.settings, task.sessionID, task.req, task.opts, task.input, decision)
	defaultTracker.completeAsyncAudit(
		task.sessionID,
		finishedAt,
		task.settings.sessionTTL,
		task.settings.blockedSessionTTL,
		task.settings.asyncRetryDelay,
		task.settings.usesBlockedBans(),
		decision,
	)

	log.WithFields(log.Fields{
		"provider":        "codex",
		"session_id":      task.sessionID,
		"blocked":         decision.Blocked,
		"observe_only":    decision.ObserveOnly,
		"error":           decision.Error,
		"mode":            task.settings.mode,
		"debug":           task.settings.debug,
		"decision_source": DecisionSourceFreshAudit,
	}).Debug("risk control: completed async codex audit")

	if shouldRecordObserveEvent(task.settings, decision) {
		recordCodexObserveEvent(finishedAt, task.settings, task.sessionID, task.req, task.opts, task.input, decision, DecisionSourceFreshAudit)
	}
	if decision.Blocked && shouldRecordBlockedEvent(task.settings, decision) {
		recordCodexBlockedEvent(finishedAt, task.settings, task.sessionID, task.req, task.opts, task.input, decision, DecisionSourceFreshAudit, riskControlBlockMessage(task.settings, decision))
	}
}

func asyncAuditEnqueueFailureDecision(err error) Decision {
	message := "async audit enqueue failed"
	if err != nil {
		message = err.Error()
	}
	return Decision{
		Blocked:      false,
		Reason:       "async audit unavailable",
		Error:        message,
		FailureClass: "audit_enqueue_failed",
	}
}

func cloneMetadata(meta map[string]any) map[string]any {
	if len(meta) == 0 {
		return nil
	}
	cloned := make(map[string]any, len(meta))
	for key, value := range meta {
		cloned[key] = value
	}
	return cloned
}

func cloneHeader(header http.Header) http.Header {
	if header == nil {
		return nil
	}
	return header.Clone()
}
