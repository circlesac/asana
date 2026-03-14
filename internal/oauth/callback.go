package oauth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

type CallbackResult struct {
	Code  string
	State string
	Err   error
}

func StartCallbackServer(port int) (result <-chan CallbackResult, shutdown func(), err error) {
	ch := make(chan CallbackResult, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if errMsg := q.Get("error"); errMsg != "" {
			ch <- CallbackResult{Err: fmt.Errorf("oauth error: %s - %s", errMsg, q.Get("error_description"))}
		} else {
			ch <- CallbackResult{
				Code:  q.Get("code"),
				State: q.Get("state"),
			}
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h2>Authentication successful!</h2><p>You can close this tab.</p><script>window.close()</script></body></html>`)
	})

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start callback server: %w", err)
	}

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		_ = srv.Serve(listener)
	}()

	shutdownFn := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}

	return ch, shutdownFn, nil
}
