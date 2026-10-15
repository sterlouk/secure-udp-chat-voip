package com.cn2.communication;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypts and authenticates datagrams with AES-256-GCM under a key derived
 * from a passphrase both peers know.
 *
 * Wire format (all integers big-endian):
 *
 * <pre>
 * +---------+------+-----------+----------+--------------+----------+----------------------+
 * | version | type | sender id | sequence | timestamp ms |  nonce   | ciphertext + GCM tag |
 * |   1 B   | 1 B  |    8 B    |   8 B    |     8 B      |  12 B    |      n + 16 B        |
 * +---------+------+-----------+----------+--------------+----------+----------------------+
 *  \_____________________ authenticated header (AAD) ______________/
 * </pre>
 *
 * The header is not secret but is covered by the GCM tag, so it cannot be
 * modified. On receive, packets are rejected for: wrong version or type,
 * our own sender id (reflection), a timestamp outside {@link #MAX_CLOCK_SKEW_MS},
 * a sequence number already seen (replay), or a failed tag check.
 */
public final class SecureChannel {

	public enum Type {
		CHAT((byte) 1), VOICE((byte) 2);

		final byte code;

		Type(byte code) {
			this.code = code;
		}
	}

	static final byte VERSION = 1;
	static final int HEADER_LEN = 1 + 1 + 8 + 8 + 8;
	static final int NONCE_LEN = 12;
	static final int TAG_LEN = 16;
	/** Bytes added to every plaintext. */
	public static final int OVERHEAD = HEADER_LEN + NONCE_LEN + TAG_LEN;
	static final long MAX_CLOCK_SKEW_MS = 60_000;

	static final int KDF_ITERATIONS = 600_000;
	private static final byte[] KDF_SALT = "cn2-chat-voip/v1".getBytes(StandardCharsets.UTF_8);
	private static final int MAX_TRACKED_SENDERS = 32;

	private final SecretKey key;
	private final long senderId;
	private final Clock clock;
	private final SecureRandom random = new SecureRandom();
	private final AtomicLong[] nextSeq = { new AtomicLong(), new AtomicLong(), new AtomicLong() };
	private final Map<String, ReplayWindow> windows = new LinkedHashMap<String, ReplayWindow>(16, 0.75f, true) {
		private static final long serialVersionUID = 1L;

		@Override
		protected boolean removeEldestEntry(Map.Entry<String, ReplayWindow> eldest) {
			return size() > MAX_TRACKED_SENDERS;
		}
	};

	public SecureChannel(SecretKey key) {
		this(key, new SecureRandom().nextLong(), Clock.systemUTC());
	}

	SecureChannel(SecretKey key, long senderId, Clock clock) {
		this.key = key;
		this.senderId = senderId;
		this.clock = clock;
	}

	/**
	 * Derives a 256-bit AES key from a passphrase with PBKDF2-HMAC-SHA256.
	 * The passphrase array is wiped afterwards.
	 */
	public static SecretKey deriveKey(char[] passphrase) throws GeneralSecurityException {
		PBEKeySpec spec = new PBEKeySpec(passphrase, KDF_SALT, KDF_ITERATIONS, 256);
		try {
			byte[] raw = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
			SecretKey key = new SecretKeySpec(raw, "AES");
			Arrays.fill(raw, (byte) 0);
			return key;
		} finally {
			spec.clearPassword();
			Arrays.fill(passphrase, '\0');
		}
	}

	public byte[] seal(Type type, byte[] plaintext, int offset, int length) throws GeneralSecurityException {
		byte[] nonce = new byte[NONCE_LEN];
		random.nextBytes(nonce);

		ByteBuffer packet = ByteBuffer.allocate(OVERHEAD + length);
		packet.put(VERSION)
				.put(type.code)
				.putLong(senderId)
				.putLong(nextSeq[type.code].getAndIncrement())
				.putLong(clock.millis())
				.put(nonce);

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LEN * 8, nonce));
		cipher.updateAAD(packet.array(), 0, HEADER_LEN);
		cipher.doFinal(plaintext, offset, length, packet.array(), HEADER_LEN + NONCE_LEN);
		return packet.array();
	}

	public byte[] open(Type expected, byte[] data, int offset, int length) throws PacketRejectedException {
		if (length < OVERHEAD) throw new PacketRejectedException(PacketRejectedException.Reason.MALFORMED);

		ByteBuffer header = ByteBuffer.wrap(data, offset, HEADER_LEN);
		byte version = header.get();
		byte type = header.get();
		long sender = header.getLong();
		long seq = header.getLong();
		long timestamp = header.getLong();

		if (version != VERSION) throw new PacketRejectedException(PacketRejectedException.Reason.MALFORMED);
		if (type != expected.code) throw new PacketRejectedException(PacketRejectedException.Reason.WRONG_TYPE);
		if (sender == senderId) throw new PacketRejectedException(PacketRejectedException.Reason.REFLECTED);
		if (Math.abs(clock.millis() - timestamp) > MAX_CLOCK_SKEW_MS) {
			throw new PacketRejectedException(PacketRejectedException.Reason.STALE);
		}

		// Look up the window without creating it: unauthenticated packets must not change any state
		String windowKey = sender + "/" + type;
		ReplayWindow window;
		synchronized (windows) {
			window = windows.get(windowKey);
		}
		if (window != null && !window.isFresh(seq)) {
			throw new PacketRejectedException(PacketRejectedException.Reason.REPLAYED);
		}

		byte[] plaintext;
		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LEN * 8, data, offset + HEADER_LEN, NONCE_LEN));
			cipher.updateAAD(data, offset, HEADER_LEN);
			plaintext = cipher.doFinal(data, offset + HEADER_LEN + NONCE_LEN, length - HEADER_LEN - NONCE_LEN);
		} catch (AEADBadTagException e) {
			throw new PacketRejectedException(PacketRejectedException.Reason.AUTH_FAILED);
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("AES-GCM unavailable", e);
		}

		synchronized (windows) {
			window = windows.computeIfAbsent(windowKey, k -> new ReplayWindow());
		}
		if (!window.checkAndMark(seq)) {
			// Lost a race with an identical packet authenticated on another thread
			throw new PacketRejectedException(PacketRejectedException.Reason.REPLAYED);
		}
		return plaintext;
	}
}
