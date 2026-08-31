package ingest

import (
	"context"
	"errors"
	"fmt"

	"github.com/hoardcti/ingest/internal/store"
)

// Processing stages, used as the dead-letter label and in metrics.
const (
	StageDecode       = "decode"
	StageValidate     = "validate"
	StageArchive      = "archive"
	StageCanonicalise = "canonicalise"
	StageWrite        = "write"
)

// PermanentError marks a failure that retrying cannot fix.
//
// The distinction is the whole of the queue's error handling. A malformed
// envelope will be malformed on every redelivery, so it is dead-lettered and
// acknowledged; a database that is down will come back, so the message is left
// unacknowledged and redelivered. Getting this backwards gives you either a
// poison message that stalls the consumer group forever, or silent data loss
// during an outage.
type PermanentError struct {
	Stage string
	Err   error
}

func (e *PermanentError) Error() string {
	return fmt.Sprintf("%s: %v", e.Stage, e.Err)
}

func (e *PermanentError) Unwrap() error { return e.Err }

// Permanent wraps err as unretryable.
func Permanent(stage string, err error) error {
	return &PermanentError{Stage: stage, Err: err}
}

// IsPermanent reports whether err should be dead-lettered rather than retried.
func IsPermanent(err error) bool {
	var pe *PermanentError
	return errors.As(err, &pe)
}

// Stage returns the processing stage a failure came from, or "unknown".
func Stage(err error) string {
	var pe *PermanentError
	if errors.As(err, &pe) {
		return pe.Stage
	}
	return "unknown"
}

// classifyWriteError decides whether a failed write is worth retrying.
//
// An unknown or disabled source is a configuration fact, not a transient one:
// redelivering the envelope every few minutes until someone notices is worse
// than parking it with the reason attached. Everything else — connection
// failures, deadlocks, timeouts, disk pressure — is assumed transient, because
// the cost of wrongly retrying is a delay and the cost of wrongly discarding is
// intelligence you cannot get back.
func classifyWriteError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, store.ErrUnknownSource), errors.Is(err, store.ErrSourceDisabled):
		return Permanent(StageWrite, err)
	default:
		return err
	}
}
