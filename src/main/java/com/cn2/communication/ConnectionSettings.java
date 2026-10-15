package com.cn2.communication;

import java.net.InetAddress;
import java.net.UnknownHostException;

/** Validated peer address and ports entered in the startup dialog. */
final class ConnectionSettings {

	static final int MIN_PASSPHRASE_LENGTH = 12;

	final InetAddress peer;
	final int chatSendPort;
	final int chatReceivePort;
	final int voiceSendPort;
	final int voiceReceivePort;

	private ConnectionSettings(InetAddress peer, int chatSendPort, int chatReceivePort, int voiceSendPort, int voiceReceivePort) {
		this.peer = peer;
		this.chatSendPort = chatSendPort;
		this.chatReceivePort = chatReceivePort;
		this.voiceSendPort = voiceSendPort;
		this.voiceReceivePort = voiceReceivePort;
	}

	/** Thrown with a user-facing message when the input is invalid. */
	static final class InvalidSettingsException extends Exception {
		private static final long serialVersionUID = 1L;

		InvalidSettingsException(String message) {
			super(message);
		}
	}

	static ConnectionSettings parse(String peerHost, String chatSend, String chatReceive, String voiceSend,
			String voiceReceive, char[] passphrase) throws InvalidSettingsException {
		if (peerHost == null || peerHost.trim().isEmpty()) throw new InvalidSettingsException("Enter the peer's IP address.");
		InetAddress peer;
		try {
			peer = InetAddress.getByName(peerHost.trim());
		} catch (UnknownHostException e) {
			throw new InvalidSettingsException("Unknown host: " + peerHost.trim());
		}

		int cs = port("Chat send port", chatSend);
		int cr = port("Chat receive port", chatReceive);
		int vs = port("Voice send port", voiceSend);
		int vr = port("Voice receive port", voiceReceive);
		if (cr == vr) throw new InvalidSettingsException("Chat and voice must use different receive ports.");

		if (passphrase == null || passphrase.length < MIN_PASSPHRASE_LENGTH) {
			throw new InvalidSettingsException("Use a shared passphrase of at least " + MIN_PASSPHRASE_LENGTH + " characters.");
		}
		return new ConnectionSettings(peer, cs, cr, vs, vr);
	}

	private static int port(String name, String value) throws InvalidSettingsException {
		try {
			int p = Integer.parseInt(value == null ? "" : value.trim());
			if (p >= 1024 && p <= 65535) return p;
		} catch (NumberFormatException ignored) {
			// fall through
		}
		throw new InvalidSettingsException(name + " must be a number between 1024 and 65535.");
	}
}
