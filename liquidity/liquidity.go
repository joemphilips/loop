// Package liquidity is responsible for monitoring our node's liquidity. It
// allows setting of a liquidity rule which describes the desired liquidity
// balance on a per-channel basis.
//
// Swap suggestions are limited to channels that are not currently being used
// for a pending swap. If we are currently processing an unrestricted swap (ie,
// a loop out with no outgoing channel targets set or a loop in with no last
// hop set), we will not suggest any swaps because these swaps will shift the
// balances of our channels in ways we can't predict.
//
// Fee restrictions are placed on swap suggestions to ensure that we only
// suggest swaps that fit the configured fee preferences.
// - Sweep Fee Rate Limit: the maximum sat/vByte fee estimate for our sweep
//   transaction to confirm within our configured number of confirmations
//   that we will suggest swaps for.
package liquidity

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcutil"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/loop"
	"github.com/lightninglabs/loop/loopdb"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
)

const (
	// defaultFailureBackoff is the default amount of time we backoff if
	// a channel is part of a temporarily failed swap.
	defaultFailureBackoff = time.Hour * 24

	// FeeBase is the base that we use to express fees.
	FeeBase = 1e6

	// defaultSwapFeePPM is the default limit we place on swap fees,
	// expressed as parts per million of swap volume, 0.5%.
	defaultSwapFeePPM = 5000

	// defaultRoutingFeePPM is the default limit we place on routing fees
	// for the swap invoice, expressed as parts per million of swap volume,
	// 1%.
	defaultRoutingFeePPM = 10000

	// defaultRoutingFeePPM is the default limit we place on routing fees
	// for the prepay invoice, expressed as parts per million of prepay
	// volume, 0.5%.
	defaultPrepayRoutingFeePPM = 5000

	// defaultMaximumMinerFee is the default limit we place on miner fees
	// per swap.
	defaultMaximumMinerFee = 15000

	// defaultMaximumPrepay is the default limit we place on prepay
	// invoices.
	defaultMaximumPrepay = 30000

	// defaultSweepFeeRateLimit is the default limit we place on estimated
	// sweep fees, (750 * 4 /1000 = 3 sat/vByte).
	defaultSweepFeeRateLimit = chainfee.SatPerKWeight(750)
)

var (
	// defaultParameters contains the default parameters that we start our
	// liquidity manger with.
	defaultParameters = Parameters{
		ChannelRules:      make(map[lnwire.ShortChannelID]*ThresholdRule),
		FailureBackOff:    defaultFailureBackoff,
		SweepFeeRateLimit: defaultSweepFeeRateLimit,
		SweepConfTarget:   loop.DefaultSweepConfTarget,
	}

	// ErrZeroChannelID is returned if we get a rule for a 0 channel ID.
	ErrZeroChannelID = fmt.Errorf("zero channel ID not allowed")

	// ErrInvalidSweepFeeRateLimit is returned if an invalid sweep fee limit
	// is set.
	ErrInvalidSweepFeeRateLimit = fmt.Errorf("sweep fee rate limit must "+
		"be > %v sat/vByte",
		satPerKwToSatPerVByte(chainfee.AbsoluteFeePerKwFloor))
)

// Config contains the external functionality required to run the
// liquidity manager.
type Config struct {
	// LoopOutRestrictions returns the restrictions that the server applies
	// to loop out swaps.
	LoopOutRestrictions func(ctx context.Context) (*Restrictions, error)

	// Lnd provides us with access to lnd's rpc servers.
	Lnd *lndclient.LndServices

	// ListLoopOut returns all of the loop our swaps stored on disk.
	ListLoopOut func() ([]*loopdb.LoopOut, error)

	// ListLoopIn returns all of the loop in swaps stored on disk.
	ListLoopIn func() ([]*loopdb.LoopIn, error)

	// Clock allows easy mocking of time in unit tests.
	Clock clock.Clock

	// MinimumConfirmations is the minimum number of confirmations we allow
	// setting for sweep target.
	MinimumConfirmations int32
}

// Parameters is a set of parameters provided by the user which guide
// how we assess liquidity.
type Parameters struct {
	// FailureBackOff is the amount of time that we require passes after a
	// channel has been part of a failed loop out swap before we suggest
	// using it again.
	// TODO(carla): add exponential backoff
	FailureBackOff time.Duration

	// SweepFeeRateLimit is the limit that we place on our estimated sweep
	// fee. A swap will not be suggested if estimated fee rate is above this
	// value.
	SweepFeeRateLimit chainfee.SatPerKWeight

	// SweepConfTarget is the number of blocks we aim to confirm our sweep
	// transaction in. This value affects the on chain fees we will pay.
	SweepConfTarget int32

	// ChannelRules maps a short channel ID to a rule that describes how we
	// would like liquidity to be managed.
	ChannelRules map[lnwire.ShortChannelID]*ThresholdRule
}

// String returns the string representation of our parameters.
func (p Parameters) String() string {
	channelRules := make([]string, 0, len(p.ChannelRules))

	for channel, rule := range p.ChannelRules {
		channelRules = append(
			channelRules, fmt.Sprintf("%v: %v", channel, rule),
		)
	}

	return fmt.Sprintf("channel rules: %v, failure backoff: %v, sweep "+
		"fee rate limit: %v, sweep conf target: %v",
		strings.Join(channelRules, ","), p.FailureBackOff,
		p.SweepFeeRateLimit, p.SweepConfTarget,
	)
}

// validate checks whether a set of parameters is valid. It takes the minimum
// confirmations we allow for sweep confirmation target as a parameter.
func (p Parameters) validate(minConfs int32) error {
	for channel, rule := range p.ChannelRules {
		if channel.ToUint64() == 0 {
			return ErrZeroChannelID
		}

		if err := rule.validate(); err != nil {
			return fmt.Errorf("channel: %v has invalid rule: %v",
				channel.ToUint64(), err)
		}
	}

	// Check that our sweep limit is above our minimum fee rate. We use
	// absolute fee floor rather than kw floor because we will allow users
	// to specify fee rate is sat/vByte and want to allow 1 sat/vByte.
	if p.SweepFeeRateLimit < chainfee.AbsoluteFeePerKwFloor {
		return ErrInvalidSweepFeeRateLimit
	}

	// Check that our confirmation target is above our required minimum.
	if p.SweepConfTarget < minConfs {
		return fmt.Errorf("confirmation target must be at least: %v",
			minConfs)
	}

	return nil
}

// Manager contains a set of desired liquidity rules for our channel
// balances.
type Manager struct {
	// cfg contains the external functionality we require to determine our
	// current liquidity balance.
	cfg *Config

	// params is the set of parameters we are currently using. These may be
	// updated at runtime.
	params Parameters

	// paramsLock is a lock for our current set of parameters.
	paramsLock sync.Mutex
}

// NewManager creates a liquidity manager which has no rules set.
func NewManager(cfg *Config) *Manager {
	return &Manager{
		cfg:    cfg,
		params: defaultParameters,
	}
}

// GetParameters returns a copy of our current parameters.
func (m *Manager) GetParameters() Parameters {
	m.paramsLock.Lock()
	defer m.paramsLock.Unlock()

	return cloneParameters(m.params)
}

// SetParameters updates our current set of parameters if the new parameters
// provided are valid.
func (m *Manager) SetParameters(params Parameters) error {
	if err := params.validate(m.cfg.MinimumConfirmations); err != nil {
		return err
	}

	m.paramsLock.Lock()
	defer m.paramsLock.Unlock()

	m.params = cloneParameters(params)
	return nil
}

// cloneParameters creates a deep clone of a parameters struct so that callers
// cannot mutate our parameters. Although our parameters struct itself is not
// a reference, we still need to clone the contents of maps.
func cloneParameters(params Parameters) Parameters {
	paramCopy := params
	paramCopy.ChannelRules = make(
		map[lnwire.ShortChannelID]*ThresholdRule,
		len(params.ChannelRules),
	)

	for channel, rule := range params.ChannelRules {
		ruleCopy := *rule
		paramCopy.ChannelRules[channel] = &ruleCopy
	}

	return paramCopy
}

// SuggestSwaps returns a set of swap suggestions based on our current liquidity
// balance for the set of rules configured for the manager, failing if there are
// no rules set.
func (m *Manager) SuggestSwaps(ctx context.Context) (
	[]loop.OutRequest, error) {

	m.paramsLock.Lock()
	defer m.paramsLock.Unlock()

	// If we have no rules set, exit early to avoid unnecessary calls to
	// lnd and the server.
	if len(m.params.ChannelRules) == 0 {
		return nil, nil
	}

	// Before we get any swap suggestions, we check what the current fee
	// estimate is to sweep within our target number of confirmations. If
	// This fee exceeds the fee limit we have set, we will not suggest any
	// swaps at present.
	estimate, err := m.cfg.Lnd.WalletKit.EstimateFee(
		ctx, m.params.SweepConfTarget,
	)
	if err != nil {
		return nil, err
	}

	if estimate > m.params.SweepFeeRateLimit {
		log.Debugf("Current fee estimate to sweep within: %v blocks "+
			"%v sat/vByte exceeds limit of: %v sat/vByte",
			m.params.SweepConfTarget,
			satPerKwToSatPerVByte(estimate),
			satPerKwToSatPerVByte(m.params.SweepFeeRateLimit))

		return nil, nil
	}

	// Get the current server side restrictions.
	outRestrictions, err := m.cfg.LoopOutRestrictions(ctx)
	if err != nil {
		return nil, err
	}

	// List our current set of swaps so that we can determine which channels
	// are already being utilized by swaps. Note that these calls may race
	// with manual initiation of swaps.
	loopOut, err := m.cfg.ListLoopOut()
	if err != nil {
		return nil, err
	}

	loopIn, err := m.cfg.ListLoopIn()
	if err != nil {
		return nil, err
	}

	eligible, err := m.getEligibleChannels(ctx, loopOut, loopIn)
	if err != nil {
		return nil, err
	}

	var suggestions []loop.OutRequest
	for _, channel := range eligible {
		channelID := lnwire.NewShortChanIDFromInt(channel.ChannelID)
		rule, ok := m.params.ChannelRules[channelID]
		if !ok {
			continue
		}

		balance := newBalances(channel)

		suggestion := rule.suggestSwap(balance, outRestrictions)

		// We can have nil suggestions in the case where no action is
		// required, so only add non-nil suggestions.
		if suggestion != nil {
			outRequest := m.makeLoopOutRequest(suggestion)
			suggestions = append(suggestions, outRequest)
		}
	}

	return suggestions, nil
}

// makeLoopOutRequest creates a loop out request from a suggestion, setting fee
// limits defined by our default fee values.
func (m *Manager) makeLoopOutRequest(suggestion *LoopOutRecommendation) loop.OutRequest {
	prepayMaxFee := ppmToSat(
		defaultMaximumPrepay, defaultPrepayRoutingFeePPM,
	)

	routeMaxFee := ppmToSat(suggestion.Amount, defaultRoutingFeePPM)
	maxSwapFee := ppmToSat(suggestion.Amount, defaultSwapFeePPM)

	return loop.OutRequest{
		Amount: suggestion.Amount,
		OutgoingChanSet: loopdb.ChannelSet{
			suggestion.Channel.ToUint64(),
		},
		MaxPrepayRoutingFee: prepayMaxFee,
		MaxSwapRoutingFee:   routeMaxFee,
		MaxMinerFee:         defaultMaximumMinerFee,
		MaxSwapFee:          maxSwapFee,
		MaxPrepayAmount:     defaultMaximumPrepay,
		SweepConfTarget:     m.params.SweepConfTarget,
	}
}

// getEligibleChannels takes lists of our existing loop out and in swaps, and
// gets a list of channels that are not currently being utilized for a swap.
// If an unrestricted swap is ongoing, we return an empty set of channels
// because we don't know which channels balances it will affect.
func (m *Manager) getEligibleChannels(ctx context.Context,
	loopOut []*loopdb.LoopOut, loopIn []*loopdb.LoopIn) (
	[]lndclient.ChannelInfo, error) {

	var (
		existingOut = make(map[lnwire.ShortChannelID]bool)
		existingIn  = make(map[route.Vertex]bool)
		failedOut   = make(map[lnwire.ShortChannelID]time.Time)
	)

	// Failure cutoff is the most recent failure timestamp we will still
	// consider a channel eligible. Any channels involved in swaps that have
	// failed since this point will not be considered.
	failureCutoff := m.cfg.Clock.Now().Add(m.params.FailureBackOff * -1)

	for _, out := range loopOut {
		var (
			state   = out.State().State
			chanSet = out.Contract.OutgoingChanSet
		)

		// If a loop out swap failed due to off chain payment after our
		// failure cutoff, we add all of its channels to a set of
		// recently failed channels. It is possible that not all of
		// these channels were used for the swap, but we play it safe
		// and back off for all of them.
		//
		// We only backoff for off temporary failures. In the case of
		// chain payment failures, our swap failed to route and we do
		// not want to repeatedly try to route through bad channels
		// which remain unbalanced because they cannot route a swap, so
		// we backoff.
		if state == loopdb.StateFailOffchainPayments {
			failedAt := out.LastUpdate().Time

			if failedAt.After(failureCutoff) {
				for _, id := range chanSet {
					chanID := lnwire.NewShortChanIDFromInt(
						id,
					)

					failedOut[chanID] = failedAt
				}
			}
		}

		// Skip completed swaps, they can't affect our channel balances.
		// Swaps that fail temporarily are considered to be in a pending
		// state, so we will also check that channels being used by
		// these swaps. This is important, because a temporarily failed
		// swap could be re-dispatched on restart, affecting our
		// balances.
		if state.Type() != loopdb.StateTypePending {
			continue
		}

		if len(chanSet) == 0 {
			log.Debugf("Ongoing unrestricted loop out: "+
				"%v, no suggestions at present", out.Hash)

			return nil, nil
		}

		for _, id := range chanSet {
			chanID := lnwire.NewShortChanIDFromInt(id)
			existingOut[chanID] = true
		}
	}

	for _, in := range loopIn {
		// Skip completed swaps, they can't affect our channel balances.
		if in.State().State.Type() != loopdb.StateTypePending {
			continue
		}

		if in.Contract.LastHop == nil {
			log.Debugf("Ongoing unrestricted loop in: "+
				"%v, no suggestions at present", in.Hash)

			return nil, nil
		}

		existingIn[*in.Contract.LastHop] = true
	}

	channels, err := m.cfg.Lnd.Client.ListChannels(ctx)
	if err != nil {
		return nil, err
	}

	// Run through our set of channels and skip over any channels that
	// are currently being utilized by a restricted swap (where restricted
	// means that a loop out limited channels, or a loop in limited last
	// hop).
	var eligible []lndclient.ChannelInfo
	for _, channel := range channels {
		shortID := lnwire.NewShortChanIDFromInt(channel.ChannelID)

		lastFail, recentFail := failedOut[shortID]
		if recentFail {
			log.Debugf("Channel: %v not eligible for "+
				"suggestions, was part of a failed swap at: %v",
				channel.ChannelID, lastFail)

			continue
		}

		if existingOut[shortID] {
			log.Debugf("Channel: %v not eligible for "+
				"suggestions, ongoing loop out utilizing "+
				"channel", channel.ChannelID)

			continue
		}

		if existingIn[channel.PubKeyBytes] {
			log.Debugf("Channel: %v not eligible for "+
				"suggestions, ongoing loop in utilizing "+
				"peer", channel.ChannelID)

			continue
		}

		eligible = append(eligible, channel)
	}

	return eligible, nil
}

// satPerKwToSatPerVByte converts sat per kWeight to sat per vByte.
func satPerKwToSatPerVByte(satPerKw chainfee.SatPerKWeight) int64 {
	return int64(satPerKw.FeePerKVByte() / 1000)
}

// ppmToSat takes an amount and a measure of parts per million for the amount
// and returns the amount that the ppm represents.
func ppmToSat(amount btcutil.Amount, ppm int) btcutil.Amount {
	return btcutil.Amount(uint64(amount) * uint64(ppm) / FeeBase)
}
