package com.cn2.communication;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import javax.sound.sampled.AudioFormat;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.LineUnavailableException;
import javax.sound.sampled.SourceDataLine;
import javax.sound.sampled.TargetDataLine;

/**
 * One encrypted VoIP call: a capture thread (mic -> encrypt -> UDP) and a
 * playback thread (UDP -> decrypt -> speaker).
 *
 * {@link #stop()} closes the sockets and audio lines, which unblocks both
 * threads and frees the port and devices, so a new call can be started.
 */
final class VoiceCall {

	/** 16 kHz, 16-bit, mono, signed, big-endian PCM. */
	static final AudioFormat FORMAT = new AudioFormat(16000f, 16, 1, true, true);
	/** 1024 bytes = 512 samples = 32 ms of audio per packet. */
	static final int FRAME_BYTES = 1024;

	private final SecureChannel channel;
	private final InetAddress peer;
	private final int sendPort;
	private final int receivePort;
	private final Consumer<String> log;

	private volatile boolean running;
	private volatile boolean muted;
	private volatile boolean deafened;
	private final AtomicLong rejected = new AtomicLong();

	private DatagramSocket sendSocket;
	private DatagramSocket receiveSocket;
	private TargetDataLine mic;
	private SourceDataLine speaker;
	private Thread captureThread;
	private Thread playbackThread;

	VoiceCall(SecureChannel channel, InetAddress peer, int sendPort, int receivePort, Consumer<String> log) {
		this.channel = channel;
		this.peer = peer;
		this.sendPort = sendPort;
		this.receivePort = receivePort;
		this.log = log;
	}

	synchronized void start() throws LineUnavailableException, SocketException {
		try {
			receiveSocket = new DatagramSocket(receivePort);
			sendSocket = new DatagramSocket();
			mic = AudioSystem.getTargetDataLine(FORMAT);
			mic.open(FORMAT);
			speaker = AudioSystem.getSourceDataLine(FORMAT);
			speaker.open(FORMAT);
		} catch (LineUnavailableException | SocketException | RuntimeException e) {
			release();
			throw e;
		}
		running = true;
		mic.start();
		speaker.start();

		captureThread = new Thread(this::captureLoop, "voice-capture");
		playbackThread = new Thread(this::playbackLoop, "voice-playback");
		captureThread.setDaemon(true);
		playbackThread.setDaemon(true);
		captureThread.start();
		playbackThread.start();
	}

	synchronized void stop() {
		if (!running) return;
		running = false;
		release();
		join(captureThread);
		join(playbackThread);
		long dropped = rejected.get();
		if (dropped > 0) log.accept("Call ended. " + dropped + " voice packet(s) were rejected (replayed, forged or wrong passphrase).");
	}

	boolean isRunning() {
		return running;
	}

	void setMuted(boolean muted) {
		this.muted = muted;
	}

	void setDeafened(boolean deafened) {
		this.deafened = deafened;
	}

	private void captureLoop() {
		byte[] frame = new byte[FRAME_BYTES];
		while (running) {
			int n = mic.read(frame, 0, frame.length);
			// Keep draining the mic while muted, otherwise its buffer overflows; just don't send
			if (n <= 0 || muted) continue;
			try {
				byte[] packet = channel.seal(SecureChannel.Type.VOICE, frame, 0, n);
				sendSocket.send(new DatagramPacket(packet, packet.length, peer, sendPort));
			} catch (IOException e) {
				if (running) log.accept("Voice send failed: " + e.getMessage());
			} catch (GeneralSecurityException e) {
				throw new IllegalStateException(e);
			}
		}
	}

	private void playbackLoop() {
		byte[] buffer = new byte[FRAME_BYTES + SecureChannel.OVERHEAD + 64];
		DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
		while (running) {
			try {
				packet.setLength(buffer.length);
				receiveSocket.receive(packet);
				byte[] pcm = channel.open(SecureChannel.Type.VOICE, packet.getData(), packet.getOffset(), packet.getLength());
				if (!deafened) speaker.write(pcm, 0, pcm.length);
			} catch (PacketRejectedException e) {
				rejected.incrementAndGet();
			} catch (IOException e) {
				// Socket closed by stop()
				if (running) log.accept("Voice receive failed: " + e.getMessage());
			}
		}
	}

	private void release() {
		if (receiveSocket != null) receiveSocket.close();
		if (sendSocket != null) sendSocket.close();
		if (mic != null) {
			mic.stop();
			mic.close();
		}
		if (speaker != null) {
			speaker.stop();
			speaker.flush();
			speaker.close();
		}
	}

	private static void join(Thread t) {
		if (t == null) return;
		try {
			t.join(1000);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}
}
