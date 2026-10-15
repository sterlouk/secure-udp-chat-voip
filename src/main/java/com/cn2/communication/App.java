package com.cn2.communication;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.SecretKey;
import javax.sound.sampled.LineUnavailableException;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

/**
 * Peer-to-peer chat and VoIP over UDP, encrypted end to end with AES-256-GCM.
 *
 * Each peer sends to the other's receive ports, so two peers use mirrored
 * settings, e.g. A sends chat to 50001 and listens on 50000, B the reverse.
 */
public class App {

	/** Keeps an encrypted chat datagram well under a typical 1500-byte MTU. */
	static final int MAX_CHAT_BYTES = 1024;
	private static final long REJECT_NOTICE_INTERVAL_MS = 5_000;
	private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss");

	private final ConnectionSettings settings;
	private final SecureChannel channel;
	private final DatagramSocket chatReceiveSocket;
	private final DatagramSocket chatSendSocket;
	private final ExecutorService sender = Executors.newSingleThreadExecutor(r -> {
		Thread t = new Thread(r, "chat-send");
		t.setDaemon(true);
		return t;
	});

	private final JFrame frame = new JFrame("Secure P2P Chat & VoIP");
	private final JTextArea conversation = new JTextArea(14, 48);
	private final JTextField input = new JTextField(32);
	private final JButton sendButton = new JButton("Send");
	private final JButton callButton = new JButton("Call");
	private final JButton hangUpButton = new JButton("Hang up");
	private final JButton muteButton = new JButton("Mute");
	private final JButton deafenButton = new JButton("Deafen");

	private VoiceCall call;
	private boolean muted;
	private boolean deafened;
	private long rejectedChat;
	private long lastRejectNotice;

	App(ConnectionSettings settings, SecretKey key) throws SocketException {
		this.settings = settings;
		this.channel = new SecureChannel(key);
		this.chatReceiveSocket = new DatagramSocket(settings.chatReceivePort);
		this.chatSendSocket = new DatagramSocket();
	}

	public static void main(String[] args) throws Exception {
		JTextField peer = new JTextField("127.0.0.1");
		JTextField chatSend = new JTextField("50001");
		JTextField chatReceive = new JTextField("50000");
		JTextField voiceSend = new JTextField("50003");
		JTextField voiceReceive = new JTextField("50002");
		JPasswordField passphrase = new JPasswordField();

		JPanel form = new JPanel(new GridLayout(0, 2, 8, 6));
		form.add(new JLabel("Peer IP address"));
		form.add(peer);
		form.add(new JLabel("Chat: send to port"));
		form.add(chatSend);
		form.add(new JLabel("Chat: listen on port"));
		form.add(chatReceive);
		form.add(new JLabel("Voice: send to port"));
		form.add(voiceSend);
		form.add(new JLabel("Voice: listen on port"));
		form.add(voiceReceive);
		form.add(new JLabel("Shared passphrase"));
		form.add(passphrase);

		while (true) {
			int choice = JOptionPane.showConfirmDialog(null, form, "Connect to peer", JOptionPane.OK_CANCEL_OPTION,
					JOptionPane.PLAIN_MESSAGE);
			if (choice != JOptionPane.OK_OPTION) System.exit(0);

			char[] secret = passphrase.getPassword();
			try {
				ConnectionSettings settings = ConnectionSettings.parse(peer.getText(), chatSend.getText(),
						chatReceive.getText(), voiceSend.getText(), voiceReceive.getText(), secret);
				SecretKey key = SecureChannel.deriveKey(secret); // also wipes `secret`
				passphrase.setText("");
				App app = new App(settings, key);
				SwingUtilities.invokeLater(app::show);
				app.startReceivingChat();
				return;
			} catch (ConnectionSettings.InvalidSettingsException e) {
				JOptionPane.showMessageDialog(null, e.getMessage(), "Invalid settings", JOptionPane.WARNING_MESSAGE);
			} catch (SocketException e) {
				JOptionPane.showMessageDialog(null, "Cannot listen on chat port " + chatReceive.getText().trim()
						+ ": " + e.getMessage(), "Port unavailable", JOptionPane.ERROR_MESSAGE);
			} finally {
				Arrays.fill(secret, '\0');
			}
		}
	}

	private void show() {
		conversation.setEditable(false);
		conversation.setLineWrap(true);
		conversation.setWrapStyleWord(true);

		JPanel compose = new JPanel(new BorderLayout(6, 0));
		compose.add(input, BorderLayout.CENTER);
		compose.add(sendButton, BorderLayout.EAST);

		JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
		controls.add(callButton);
		controls.add(hangUpButton);
		controls.add(muteButton);
		controls.add(deafenButton);

		JLabel status = new JLabel(String.format("Peer %s  |  chat %d->%d  voice %d->%d  |  AES-256-GCM",
				settings.peer.getHostAddress(), settings.chatReceivePort, settings.chatSendPort,
				settings.voiceReceivePort, settings.voiceSendPort));

		JPanel bottom = new JPanel(new BorderLayout(0, 6));
		bottom.add(compose, BorderLayout.NORTH);
		bottom.add(controls, BorderLayout.CENTER);
		bottom.add(status, BorderLayout.SOUTH);

		JPanel root = new JPanel(new BorderLayout(0, 8));
		root.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		root.add(new JScrollPane(conversation), BorderLayout.CENTER);
		root.add(bottom, BorderLayout.SOUTH);

		sendButton.addActionListener(e -> sendChat());
		input.addActionListener(e -> sendChat()); // Enter key
		callButton.addActionListener(e -> startCall());
		hangUpButton.addActionListener(e -> endCall());
		muteButton.addActionListener(e -> toggleMute());
		deafenButton.addActionListener(e -> toggleDeafen());
		updateCallButtons();

		frame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
		frame.addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent e) {
				shutdown();
			}
		});
		frame.setContentPane(root);
		frame.pack();
		frame.setLocationByPlatform(true);
		frame.setVisible(true);
		input.requestFocusInWindow();
	}

	private void sendChat() {
		String text = input.getText().trim();
		if (text.isEmpty()) return;
		byte[] plain = text.getBytes(StandardCharsets.UTF_8);
		if (plain.length > MAX_CHAT_BYTES) {
			log("Message too long (" + plain.length + " bytes, max " + MAX_CHAT_BYTES + "). Not sent.");
			return;
		}
		input.setText("");
		sender.execute(() -> {
			try {
				byte[] packet = channel.seal(SecureChannel.Type.CHAT, plain, 0, plain.length);
				chatSendSocket.send(new DatagramPacket(packet, packet.length, settings.peer, settings.chatSendPort));
				log("You: " + text);
			} catch (IOException e) {
				log("Send failed: " + e.getMessage());
			} catch (GeneralSecurityException e) {
				throw new IllegalStateException(e);
			}
		});
	}

	private void startReceivingChat() {
		Thread receiver = new Thread(() -> {
			byte[] buffer = new byte[MAX_CHAT_BYTES + SecureChannel.OVERHEAD + 256];
			DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
			while (!chatReceiveSocket.isClosed()) {
				try {
					// receive() shrinks the packet length to the last datagram; reset it or later messages get truncated
					packet.setLength(buffer.length);
					chatReceiveSocket.receive(packet);
					byte[] plain = channel.open(SecureChannel.Type.CHAT, packet.getData(), packet.getOffset(), packet.getLength());
					log("Peer: " + new String(plain, StandardCharsets.UTF_8));
				} catch (PacketRejectedException e) {
					noteRejected(packet, e);
				} catch (IOException e) {
					if (!chatReceiveSocket.isClosed()) log("Receive failed: " + e.getMessage());
				}
			}
		}, "chat-receive");
		receiver.setDaemon(true);
		receiver.start();
	}

	/** Report dropped packets without letting a flood of them spam the window. */
	private synchronized void noteRejected(DatagramPacket packet, PacketRejectedException e) {
		rejectedChat++;
		long now = System.currentTimeMillis();
		if (now - lastRejectNotice >= REJECT_NOTICE_INTERVAL_MS) {
			lastRejectNotice = now;
			log("Dropped a chat packet from " + packet.getAddress().getHostAddress() + " (" + e.reason()
					+ "). Total dropped: " + rejectedChat);
		}
	}

	private void startCall() {
		if (call != null && call.isRunning()) return;
		call = new VoiceCall(channel, settings.peer, settings.voiceSendPort, settings.voiceReceivePort, this::log);
		call.setMuted(muted);
		call.setDeafened(deafened);
		try {
			call.start();
			log("Call started.");
		} catch (LineUnavailableException e) {
			log("Microphone or speaker unavailable: " + e.getMessage());
		} catch (SocketException e) {
			log("Cannot listen on voice port " + settings.voiceReceivePort + ": " + e.getMessage());
		}
		updateCallButtons();
	}

	private void endCall() {
		if (call == null) return;
		call.stop();
		call = null;
		log("Call ended.");
		updateCallButtons();
	}

	private void toggleMute() {
		muted = !muted;
		if (call != null) call.setMuted(muted);
		updateCallButtons();
	}

	private void toggleDeafen() {
		deafened = !deafened;
		if (call != null) call.setDeafened(deafened);
		updateCallButtons();
	}

	private void updateCallButtons() {
		boolean inCall = call != null && call.isRunning();
		callButton.setEnabled(!inCall);
		hangUpButton.setEnabled(inCall);
		muteButton.setText(muted ? "Unmute" : "Mute");
		deafenButton.setText(deafened ? "Undeafen" : "Deafen");
	}

	private void log(String line) {
		String stamped = "[" + LocalTime.now().format(TIME) + "] " + line + "\n";
		SwingUtilities.invokeLater(() -> {
			conversation.append(stamped);
			conversation.setCaretPosition(conversation.getDocument().getLength());
		});
	}

	private void shutdown() {
		if (call != null) call.stop();
		chatReceiveSocket.close();
		chatSendSocket.close();
		sender.shutdownNow();
		frame.dispose();
		System.exit(0);
	}
}
