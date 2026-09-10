package internal

import "fmt"

type wrapError struct {
	err error
	ctx string
}

func (w *wrapError) Unwrap() error {
	return w.err
}

func (w wrapError) Error() string {
	return fmt.Sprintf("%s:\n\t%s", w.err.Error(), w.ctx)
}
func MaybeWrap(err error, ctx string) error {
	if err == nil {
		return nil
	}
	return wrapError{err, ctx}
}

func WrapError(err error, ctx string) error {
	return wrapError{err, ctx}
}
