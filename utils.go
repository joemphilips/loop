package loop

import (
	"bytes"
	"context"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
	"github.com/lightninglabs/lndclient"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/zpay32"
)

func FetchChannelEdgesByID(ctx context.Context, lnd *lndclient.LndServices, chanID uint64,
) ([]byte, *lndclient.RoutingPolicy, *lndclient.RoutingPolicy, error) {
	chanInfo, err := lnd.Client.GetChanInfo(ctx, chanID)
	return chanInfo.Node1[:], chanInfo.Node1Policy, chanInfo.Node2Policy, err
}

func IsPublicNode(channels []lndclient.ChannelInfo, pubKey [33]byte) bool {
	for i := range channels {
		if channels[i].PubKeyBytes == pubKey && channels[i].Private {
			return false
		}
	}
	return true
}

// chanCanBeHopHint returns true if the target channel is eligible to be a hop
// hint.
func chanCanBeHopHint(ctx context.Context, lnd *lndclient.LndServices, channels []lndclient.ChannelInfo,
	channel lndclient.ChannelInfo, chanInfo *lndclient.ChannelEdge) (
	*lndclient.RoutingPolicy, bool) {

	// To ensure we don't leak unadvertised nodes, we'll make sure our
	// counterparty is publicly advertised within the network.  Otherwise,
	// we'll end up leaking information about nodes that intend to stay
	// unadvertised, like in the case of a node only having private
	// channels.
	if !IsPublicNode(channels, channel.PubKeyBytes) {
		log.Debugf("Skipping channel %v due to "+
			"counterparty %x being unadvertised",
			channel.ChannelID, channel.PubKeyBytes[:])
		return nil, false
	}

	// Fetch the policies for each end of the channel.
	serializedPubKey, p1, p2, err := FetchChannelEdgesByID(ctx, lnd, channel.ChannelID)
	if err != nil {
		log.Errorf("Unable to fetch the routing "+
			"policies for the edges of the channel "+
			"%v: %v", channel.ChannelID, err)
		return nil, false
	}

	// Now, we'll need to determine which is the correct policy for HTLCs
	// being sent from the remote node.
	var remotePolicy *lndclient.RoutingPolicy
	if bytes.Equal(channel.PubKeyBytes[:], serializedPubKey) {
		remotePolicy = p1
	} else {
		remotePolicy = p2
	}

	return remotePolicy, true
}

func SelectHopHints(ctx context.Context, lnd *lndclient.LndServices, amtMSat btcutil.Amount,
	numMaxHophints int, include_nodes map[route.Vertex]struct{}) ([][]zpay32.HopHint, error) {

	openChannels, err := lnd.Client.ListChannels(ctx)
	if err != nil {
		return nil, err
	}
	// We'll add our hop hints in two passes, first we'll add all channels
	// that are eligible to be hop hints, and also have a local balance
	// above the payment amount.
	var totalHintBandwidth btcutil.Amount
	var chanInfo *lndclient.ChannelEdge
	hopHintChans := make(map[string]struct{})
	hopHints := make([][]zpay32.HopHint, 0, numMaxHophints)
	for _, channel := range openChannels {
		// In this first pass, we'll ignore all channels in
		// isolation can't satisfy this payment.
		if channel.RemoteBalance < amtMSat {
			continue
		}

		// If include_nodes is set, we'll only add channels with peers in include_node.
		// This is done to respect the last_hop parameter
		if _, ok := include_nodes[channel.PubKeyBytes]; include_nodes != nil && !ok {
			continue
		}

		// TODO: cache for increased performance
		chanInfo, err := lnd.Client.GetChanInfo(ctx, channel.ChannelID)
		if err != nil {
			return nil, err
		}

		// If this channel can't be a hop hint, then skip it.
		edgePolicy, canBeHopHint := chanCanBeHopHint(ctx, lnd, openChannels, channel, chanInfo)
		if edgePolicy == nil || !canBeHopHint {
			continue
		}

		// Retrieve extra info for each channel not available in listChannels
		chanInfo, err = lnd.Client.GetChanInfo(ctx, channel.ChannelID)
		if err != nil {
			return nil, err
		}

		nodeID, err := btcec.ParsePubKey(channel.PubKeyBytes[:], btcec.S256())
		if err != nil {
			return nil, err
		}

		// Now that we now this channel use usable, add it as a hop
		// hint and the indexes we'll use later.
		hopHints = append(hopHints, []zpay32.HopHint{zpay32.HopHint{
			NodeID:      nodeID,
			ChannelID:   channel.ChannelID,
			FeeBaseMSat: uint32(chanInfo.Node2Policy.FeeBaseMsat),
			FeeProportionalMillionths: uint32(
				chanInfo.Node2Policy.FeeRateMilliMsat,
			),
			CLTVExpiryDelta: uint16(chanInfo.Node2Policy.TimeLockDelta),
		}})

		hopHintChans[chanInfo.ChannelPoint] = struct{}{}
		totalHintBandwidth += channel.RemoteBalance
	}

	// If we have enough hop hints at this point, then we'll exit early.
	// Otherwise, we'll continue to add more that may help out mpp users.
	if len(hopHints) >= numMaxHophints {
		return hopHints, nil
	}

	// In this second pass we'll add channels, and we'll either stop when
	// we have 20 hop hints, we've run through all the available channels,
	// or if the sum of available bandwidth in the routing hints exceeds 2x
	// the payment amount. We do 2x here to account for a margin of error
	// if some of the selected channels no longer become operable.
	hopHintFactor := btcutil.Amount(lnwire.MilliSatoshi(2)) // cONVERT TO btcutil.Amount
	for i := 0; i < len(openChannels); i++ {
		// If we hit either of our early termination conditions, then
		// we'll break the loop here.
		if totalHintBandwidth > amtMSat*hopHintFactor ||
			len(hopHints) >= numMaxHophints {

			break
		}

		channel := openChannels[i]

		// Skip the channel if we already selected it.
		if _, ok := hopHintChans[chanInfo.ChannelPoint]; ok {
			continue
		}

		// If the channel can't be a hop hint, then we'll skip it.
		// Otherwise, we'll use the policy information to populate the
		// hop hint.
		remotePolicy, canBeHopHint := chanCanBeHopHint(ctx, lnd, openChannels, channel, chanInfo)
		if !canBeHopHint || remotePolicy == nil {
			continue
		}

		nodeID, err := btcec.ParsePubKey(channel.PubKeyBytes[:], btcec.S256())
		if err != nil {
			continue
		}

		// Include the route hint in our set of options that will be
		// used when creating the invoice.
		hopHints = append(hopHints, []zpay32.HopHint{zpay32.HopHint{
			NodeID:      nodeID,
			ChannelID:   channel.ChannelID,
			FeeBaseMSat: uint32(chanInfo.Node2Policy.FeeBaseMsat),
			FeeProportionalMillionths: uint32(
				chanInfo.Node2Policy.FeeRateMilliMsat,
			),
			CLTVExpiryDelta: uint16(chanInfo.Node2Policy.TimeLockDelta),
		}})
		// As we've just added a new hop hint, we'll accumulate it's
		// available balance now to update our tally.
		//
		// TODO(roasbeef): have a cut off based on min bandwidth?
		totalHintBandwidth += channel.RemoteBalance
	}

	return hopHints, nil
}
