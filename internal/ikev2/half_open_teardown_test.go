package ikev2

// Regression tests for the half-open IKE SA reaper's teardown path.
//
// Bug: halfOpenReaperLoop expired an abandoned IKE_AUTH/EAP-AKA' attempt by
// calling deleteSA() directly, which only removes the entry from the
// low-level s.sas map. Any higher-level session.Session, SWm Diameter
// session, or partial S2b state created during authentication was left
// behind, orphaned in the session registry (visible via the admin/session
// API even though the IKE SA itself was gone).
//
// The fix routes half-open expiry through fullTeardown, holding sa.mu across
// the timeout check and the teardown so an in-flight IKE_AUTH cannot promote
// the SA to established after the reaper has already decided to expire it
// (and vice versa).
import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"vectorcore-epdg/internal/config"
	"vectorcore-epdg/internal/session"
	"vectorcore-epdg/internal/swm"
)

// TestHalfOpenReaperRemovesAssociatedSession covers the reported symptom
// directly: an abandoned auth attempt that got as far as EAP-AKA' (session
// sitting in EAPAuthenticated) must not survive half-open expiry in the
// session registry once its IKE SA is gone.
func TestHalfOpenReaperRemovesAssociatedSession(t *testing.T) {
	srv := newLoadTestServer(t)
	srv.fullCfg = &config.Config{IKEv2: config.IKEv2Config{HalfOpenSATimeout: 1}} // ticks ~333ms

	mgr := session.NewManager()
	srv.SetSessionManager(mgr)

	const spi = uint64(101)
	const sessID = "sess-eap-authenticated"
	sess := mgr.GetOrCreate(sessID)
	sess.Lock()
	sess.IMSI = "999700000000001"
	sess.APN = "ims"
	sess.IkeSPII = spi
	_ = sess.Transition(session.StateEAPAuthenticating)
	_ = sess.Transition(session.StateEAPAuthenticated)
	sess.Unlock()

	srv.storeSA(&ikeSA{
		spiI:      spi,
		state:     ikeStateAuth,
		createdAt: time.Now().Add(-10 * time.Second),
		sessionID: sessID,
		imsi:      "999700000000001",
	})

	runReaperOnceAndStop(t, srv)

	if srv.lookupSA(spi) != nil {
		t.Error("expired half-open IKE SA was not removed")
	}
	if mgr.Get(sessID) != nil {
		t.Error("session.Session for the expired half-open SA was left behind (the reported orphan-session bug)")
	}
}

// TestHalfOpenReaperNoPanicWithoutOptionalState covers a half-open SA that
// never got far enough to acquire a session, SWm session, or S2b state (the
// common case: IKE_SA_INIT completed, UE vanished before IKE_AUTH round 1).
// fullTeardown must tolerate all of these being unset.
func TestHalfOpenReaperNoPanicWithoutOptionalState(t *testing.T) {
	srv := newLoadTestServer(t)
	srv.fullCfg = &config.Config{IKEv2: config.IKEv2Config{HalfOpenSATimeout: 1}}
	srv.SetSessionManager(session.NewManager())

	const spi = uint64(102)
	srv.storeSA(&ikeSA{
		spiI:      spi,
		state:     ikeStateAuth,
		createdAt: time.Now().Add(-10 * time.Second),
		// sessionID, swmSessionID, espProp all zero/nil.
	})

	runReaperOnceAndStop(t, srv)

	if srv.lookupSA(spi) != nil {
		t.Error("expired half-open IKE SA with no optional state was not removed")
	}
}

// TestHalfOpenReaperAttemptsSWmTermination covers a half-open SA that reached
// SWm EAP exchange (sa.swmSessionID populated) before being abandoned. STR
// should be attempted; a real (never-started, unreachable) swm.Client is used
// so the attempt fails, proving fullTeardown doesn't skip or block on it —
// consistent with fullTeardown's existing best-effort/log-and-continue
// handling of SWm STR failures elsewhere (e.g. ike_delete_by_ue, dpd_timeout).
func TestHalfOpenReaperAttemptsSWmTermination(t *testing.T) {
	srv := newLoadTestServer(t)
	srv.fullCfg = &config.Config{IKEv2: config.IKEv2Config{HalfOpenSATimeout: 1}}

	mgr := session.NewManager()
	srv.SetSessionManager(mgr)
	srv.SetSWM(swm.NewClient(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil))))

	const spi = uint64(103)
	const sessID = "sess-swm"
	sess := mgr.GetOrCreate(sessID)
	sess.Lock()
	sess.IMSI = "999700000000002"
	sess.SWMSessionID = "swm-sess-1"
	_ = sess.Transition(session.StateEAPAuthenticating)
	sess.Unlock()

	srv.storeSA(&ikeSA{
		spiI:         spi,
		state:        ikeStateAuth,
		createdAt:    time.Now().Add(-10 * time.Second),
		sessionID:    sessID,
		swmSessionID: "swm-sess-1",
	})

	// fullTeardown bounds the STR attempt to a 3s context; give the reaper
	// loop enough wall-clock time to get through one expiry pass plus that.
	runReaperFor(t, srv, 5*time.Second)

	if srv.lookupSA(spi) != nil {
		t.Error("expired half-open IKE SA with an SWm session was not removed")
	}
	if mgr.Get(sessID) != nil {
		t.Error("session with an SWm session ID was left behind after half-open expiry")
	}
}

// TestHalfOpenReaperNoDoubleTeardown covers an SA that another path (e.g. UE
// DELETE, DPD timeout) has already begun tearing down: it's no longer in
// ikeStateAuth, so the half-open reaper must leave it alone rather than
// calling fullTeardown a second time against already-cleaned-up state.
func TestHalfOpenReaperNoDoubleTeardown(t *testing.T) {
	srv := newLoadTestServer(t)
	srv.fullCfg = &config.Config{IKEv2: config.IKEv2Config{HalfOpenSATimeout: 1}}
	srv.SetSessionManager(session.NewManager())

	const spi = uint64(104)
	srv.storeSA(&ikeSA{
		spiI:      spi,
		state:     ikeStateDeleting, // another path already claimed this SA
		createdAt: time.Now().Add(-10 * time.Second),
	})

	runReaperOnceAndStop(t, srv)

	// The reaper must not touch an SA outside ikeStateAuth: it stays exactly
	// as the other (in-progress) teardown path left it, to be removed by
	// that path rather than reaped here.
	sa := srv.lookupSA(spi)
	if sa == nil {
		t.Fatal("half-open reaper removed an SA outside ikeStateAuth — it should have left it for the owning teardown path")
	}
	if sa.state != ikeStateDeleting {
		t.Errorf("SA state = %v, want unchanged ikeStateDeleting", sa.state)
	}
}

// TestHalfOpenReaperDoesNotOrphanConcurrentlyEstablishedSession is the
// concurrency regression from the bug report: authentication completing
// concurrently with half-open expiry must never leave the IKE SA map and the
// session registry inconsistent. Across many trials with real goroutine
// scheduling, the invariant "SA absent implies its session is also absent"
// must hold — that inconsistency (SA gone, session left behind) is exactly
// what shipped: the old code checked sa.state under sa.mu, released the
// lock, and then unconditionally deleted, regardless of what the
// concurrently-running IKE_AUTH final round did to the SA and session in the
// meantime.
func TestHalfOpenReaperDoesNotOrphanConcurrentlyEstablishedSession(t *testing.T) {
	const trials = 25

	for i := 0; i < trials; i++ {
		srv := newLoadTestServer(t)
		ctx, cancel := context.WithCancel(context.Background())
		srv.ctx = ctx
		srv.fullCfg = &config.Config{IKEv2: config.IKEv2Config{HalfOpenSATimeout: 1}} // ~333ms ticks

		mgr := session.NewManager()
		srv.SetSessionManager(mgr)

		spi := uint64(200 + i)
		sessID := "sess-race"
		sess := mgr.GetOrCreate(sessID)
		sess.Lock()
		sess.IMSI = "999700000000003"
		_ = sess.Transition(session.StateEAPAuthenticating)
		_ = sess.Transition(session.StateEAPAuthenticated)
		sess.Unlock()

		sa := &ikeSA{
			spiI:      spi,
			state:     ikeStateAuth,
			createdAt: time.Now().Add(-10 * time.Second), // already past the timeout
			sessionID: sessID,
		}
		srv.storeSA(sa)

		reaperDone := make(chan struct{})
		go func() {
			srv.halfOpenReaperLoop()
			close(reaperDone)
		}()

		// Race an "IKE_AUTH final round completed" transition against the
		// reaper's expiry check, exactly as handleAuthFinal does: take
		// sa.mu, and only promote if still in ikeStateAuth.
		authDone := make(chan struct{})
		go func() {
			defer close(authDone)
			if i%2 == 0 {
				time.Sleep(time.Duration(i%5) * time.Millisecond)
			}
			sa.mu.Lock()
			if sa.state == ikeStateAuth {
				sa.state = ikeStateEstablished
				sess.Lock()
				_ = sess.Transition(session.StateS2BCreateSessionSent)
				_ = sess.Transition(session.StateS2BAccepted)
				_ = sess.Transition(session.StateGTPUInstalling)
				_ = sess.Transition(session.StateDatapathInstalling)
				_ = sess.Transition(session.StateActive)
				sess.Unlock()
			}
			sa.mu.Unlock()
		}()

		<-authDone
		time.Sleep(400 * time.Millisecond) // let the reaper get at least one tick in
		cancel()
		select {
		case <-reaperDone:
		case <-time.After(2 * time.Second):
			t.Fatalf("trial %d: halfOpenReaperLoop did not exit after ctx cancellation", i)
		}

		saGone := srv.lookupSA(spi) == nil
		sessGone := mgr.Get(sessID) == nil
		if saGone && !sessGone {
			t.Fatalf("trial %d: IKE SA was removed but its session survived — orphaned session (the reported bug)", i)
		}
		if !saGone && sessGone {
			t.Fatalf("trial %d: session was removed but its IKE SA survived — inconsistent teardown", i)
		}
	}
}

// runReaperOnceAndStop runs halfOpenReaperLoop long enough for one expiry
// pass, then cancels srv.ctx and waits for the loop to exit.
func runReaperOnceAndStop(t *testing.T, srv *Server) {
	t.Helper()
	runReaperFor(t, srv, 1500*time.Millisecond)
}

// runReaperFor runs halfOpenReaperLoop for the given duration (to allow any
// bounded blocking work inside fullTeardown, e.g. an SWm STR attempt against
// an unreachable peer, to resolve within a tick), then cancels srv.ctx and
// waits for the loop to exit.
func runReaperFor(t *testing.T, srv *Server, d time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	srv.ctx = ctx

	done := make(chan struct{})
	go func() {
		srv.halfOpenReaperLoop()
		close(done)
	}()

	time.Sleep(d)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("halfOpenReaperLoop did not exit after ctx cancellation")
	}
}
