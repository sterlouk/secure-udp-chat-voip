package com.cn2.communication;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.cn2.communication.PacketRejectedException.Reason;
import com.cn2.communication.SecureChannel.Type;

class SecureChannelTest {

	private static final Clock NOW = Clock.fixed(Instant.parse("2025-01-21T12:00:00Z"), ZoneOffset.UTC);
	private static SecretKey key;
	private static SecretKey otherKey;

	@BeforeAll
	static void deriveKeys() throws Exception {
		key = SecureChannel.deriveKey("correct horse battery staple".toCharArray());
		otherKey = SecureChannel.deriveKey("a different passphrase".toCharArray());
	}

	private static SecureChannel alice() {
		return new SecureChannel(key, 1L, NOW);
	}

	private static SecureChannel bob() {
		return new SecureChannel(key, 2L, NOW);
	}

	private static byte[] utf8(String s) {
		return s.getBytes(StandardCharsets.UTF_8);
	}

	private static Reason rejection(SecureChannel receiver, Type type, byte[] packet) {
		return assertThrows(PacketRejectedException.class, () -> receiver.open(type, packet, 0, packet.length)).reason();
	}

	@Test
	void roundTripsChatAndVoice() throws Exception {
		SecureChannel a = alice(), b = bob();
		byte[] msg = utf8("Γεια σου! héllo 👋");
		byte[] packet = a.seal(Type.CHAT, msg, 0, msg.length);
		assertArrayEquals(msg, b.open(Type.CHAT, packet, 0, packet.length));

		byte[] pcm = new byte[VoiceCall.FRAME_BYTES];
		pcm[7] = 42;
		byte[] voice = a.seal(Type.VOICE, pcm, 0, pcm.length);
		assertArrayEquals(pcm, b.open(Type.VOICE, voice, 0, voice.length));
	}

	@Test
	void ciphertextDoesNotContainPlaintext() throws Exception {
		byte[] msg = utf8("meet at the library at 5");
		byte[] packet = alice().seal(Type.CHAT, msg, 0, msg.length);
		assertFalse(new String(packet, StandardCharsets.ISO_8859_1).contains("library"));
		assertEquals(msg.length + SecureChannel.OVERHEAD, packet.length);
	}

	@Test
	void sameMessageEncryptsDifferentlyEachTime() throws Exception {
		SecureChannel a = alice();
		byte[] msg = utf8("hi");
		byte[] p1 = a.seal(Type.CHAT, msg, 0, msg.length);
		byte[] p2 = a.seal(Type.CHAT, msg, 0, msg.length);
		assertFalse(java.util.Arrays.equals(p1, p2));
	}

	@Test
	void flippingAnyByteIsDetected() throws Exception {
		byte[] msg = utf8("transfer 10 EUR");
		byte[] original = alice().seal(Type.CHAT, msg, 0, msg.length);
		for (int i = 0; i < original.length; i++) {
			byte[] tampered = original.clone();
			tampered[i] ^= 0x01;
			// Fresh receiver each time so earlier attempts can't affect the replay state
			Reason reason = rejection(bob(), Type.CHAT, tampered);
			// Header bytes may trip a cheaper check first; anything else must fail authentication
			if (i >= SecureChannel.HEADER_LEN) assertEquals(Reason.AUTH_FAILED, reason, "byte " + i);
		}
	}

	@Test
	void wrongPassphraseIsRejected() throws Exception {
		byte[] msg = utf8("secret");
		byte[] packet = new SecureChannel(otherKey, 1L, NOW).seal(Type.CHAT, msg, 0, msg.length);
		assertEquals(Reason.AUTH_FAILED, rejection(bob(), Type.CHAT, packet));
	}

	@Test
	void replayedPacketIsRejected() throws Exception {
		SecureChannel b = bob();
		byte[] msg = utf8("pay once");
		byte[] packet = alice().seal(Type.CHAT, msg, 0, msg.length);
		b.open(Type.CHAT, packet, 0, packet.length);
		assertEquals(Reason.REPLAYED, rejection(b, Type.CHAT, packet));
	}

	@Test
	void forgedPacketDoesNotPoisonReplayWindow() throws Exception {
		SecureChannel a = alice(), b = bob();
		// Attacker forges a header claiming a huge sequence number; it fails auth...
		byte[] msg = utf8("x");
		byte[] forged = a.seal(Type.CHAT, msg, 0, msg.length);
		ByteBuffer.wrap(forged).putLong(10, 1_000_000L);
		assertEquals(Reason.AUTH_FAILED, rejection(b, Type.CHAT, forged));
		// ...and must not have advanced the window past Alice's real packets
		byte[] real = a.seal(Type.CHAT, msg, 0, msg.length);
		assertArrayEquals(msg, b.open(Type.CHAT, real, 0, real.length));
	}

	@Test
	void reflectedPacketIsRejected() throws Exception {
		SecureChannel a = alice();
		byte[] msg = utf8("echo");
		byte[] packet = a.seal(Type.CHAT, msg, 0, msg.length);
		assertEquals(Reason.REFLECTED, rejection(a, Type.CHAT, packet));
	}

	@Test
	void voicePacketIsNotAcceptedAsChat() throws Exception {
		byte[] pcm = new byte[32];
		byte[] packet = alice().seal(Type.VOICE, pcm, 0, pcm.length);
		assertEquals(Reason.WRONG_TYPE, rejection(bob(), Type.CHAT, packet));
	}

	@Test
	void stalePacketIsRejected() throws Exception {
		Clock twoMinutesAgo = Clock.offset(NOW, Duration.ofMinutes(-2));
		byte[] msg = utf8("old");
		byte[] packet = new SecureChannel(key, 1L, twoMinutesAgo).seal(Type.CHAT, msg, 0, msg.length);
		assertEquals(Reason.STALE, rejection(bob(), Type.CHAT, packet));
	}

	@Test
	void truncatedPacketIsMalformed() {
		byte[] tooShort = new byte[SecureChannel.OVERHEAD - 1];
		assertEquals(Reason.MALFORMED, rejection(bob(), Type.CHAT, tooShort));
	}

	@Test
	void deriveKeyWipesPassphrase() throws Exception {
		char[] secret = "wipe me after use".toCharArray();
		SecureChannel.deriveKey(secret);
		for (char c : secret) assertEquals('\0', c);
	}

	@Test
	void worksOverRealUdpSockets() throws Exception {
		SecureChannel a = new SecureChannel(key), b = new SecureChannel(key);
		try (DatagramSocket receiver = new DatagramSocket(0, InetAddress.getLoopbackAddress());
				DatagramSocket senderSocket = new DatagramSocket()) {
			receiver.setSoTimeout(2000);
			byte[] buffer = new byte[2048];
			DatagramPacket in = new DatagramPacket(buffer, buffer.length);

			// Reuses one DatagramPacket like the app's receive loops: a long message after a short one
			// only arrives intact because the length is reset before each receive()
			for (String text : new String[] { "hi", "this message is much longer than the first one" }) {
				byte[] msg = utf8(text);
				byte[] out = a.seal(Type.CHAT, msg, 0, msg.length);
				senderSocket.send(new DatagramPacket(out, out.length, InetAddress.getLoopbackAddress(), receiver.getLocalPort()));
				in.setLength(buffer.length);
				receiver.receive(in);
				assertEquals(text, new String(b.open(Type.CHAT, in.getData(), in.getOffset(), in.getLength()), StandardCharsets.UTF_8));
			}
		}
	}
}
