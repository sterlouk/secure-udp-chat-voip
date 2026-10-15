package com.cn2.communication;

/**
 * Sliding-window replay filter (same idea as IPsec/DTLS anti-replay).
 *
 * Tracks the highest sequence number seen plus a 64-bit bitmap of the
 * 64 numbers below it. Packets may arrive out of order within the window,
 * but each sequence number is accepted at most once, and anything older
 * than the window is rejected.
 */
final class ReplayWindow {

	static final int SIZE = 64;

	private long highest = -1;
	/** Bit i set means sequence number (highest - i) has been seen. */
	private long seen;

	/** Read-only check: would this sequence number be accepted? */
	synchronized boolean isFresh(long seq) {
		if (seq < 0) return false;
		if (highest < 0 || seq > highest) return true;
		long age = highest - seq;
		if (age >= SIZE) return false;
		return (seen & (1L << age)) == 0;
	}

	/** Atomically accept a sequence number if fresh. Call only after the packet has been authenticated. */
	synchronized boolean checkAndMark(long seq) {
		if (!isFresh(seq)) return false;
		markSeen(seq);
		return true;
	}

	private void markSeen(long seq) {
		if (highest < 0) {
			highest = seq;
			seen = 1L;
		} else if (seq > highest) {
			long shift = seq - highest;
			seen = shift >= SIZE ? 1L : (seen << shift) | 1L;
			highest = seq;
		} else {
			seen |= 1L << (highest - seq);
		}
	}
}
