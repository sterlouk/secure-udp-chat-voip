package com.cn2.communication;

/** Thrown when an incoming datagram fails validation and must be dropped. */
public final class PacketRejectedException extends Exception {

	private static final long serialVersionUID = 1L;

	public enum Reason {
		/** Too short or unknown protocol version. */
		MALFORMED,
		/** A voice packet sent to the chat port or vice versa. */
		WRONG_TYPE,
		/** Our own packet bounced back to us. */
		REFLECTED,
		/** Timestamp outside the allowed clock skew. */
		STALE,
		/** Sequence number already seen or older than the replay window. */
		REPLAYED,
		/** AES-GCM tag check failed: tampered, forged, or wrong passphrase. */
		AUTH_FAILED
	}

	private final Reason reason;

	PacketRejectedException(Reason reason) {
		super(reason.name());
		this.reason = reason;
	}

	public Reason reason() {
		return reason;
	}
}
