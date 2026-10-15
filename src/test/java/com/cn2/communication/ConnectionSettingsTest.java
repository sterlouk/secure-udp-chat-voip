package com.cn2.communication;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import com.cn2.communication.ConnectionSettings.InvalidSettingsException;

class ConnectionSettingsTest {

	private static final char[] GOOD_PASS = "long enough passphrase".toCharArray();

	@Test
	void parsesValidSettings() throws Exception {
		ConnectionSettings s = ConnectionSettings.parse(" 127.0.0.1 ", "50001", "50000", "50003", "50002", GOOD_PASS);
		assertEquals("127.0.0.1", s.peer.getHostAddress());
		assertEquals(50001, s.chatSendPort);
		assertEquals(50002, s.voiceReceivePort);
	}

	@Test
	void rejectsBadPorts() {
		assertThrows(InvalidSettingsException.class, () -> ConnectionSettings.parse("127.0.0.1", "abc", "50000", "50003", "50002", GOOD_PASS));
		assertThrows(InvalidSettingsException.class, () -> ConnectionSettings.parse("127.0.0.1", "80", "50000", "50003", "50002", GOOD_PASS));
		assertThrows(InvalidSettingsException.class, () -> ConnectionSettings.parse("127.0.0.1", "70000", "50000", "50003", "50002", GOOD_PASS));
	}

	@Test
	void rejectsSameReceivePortForChatAndVoice() {
		assertThrows(InvalidSettingsException.class, () -> ConnectionSettings.parse("127.0.0.1", "50001", "50000", "50003", "50000", GOOD_PASS));
	}

	@Test
	void rejectsShortPassphrase() {
		assertThrows(InvalidSettingsException.class, () -> ConnectionSettings.parse("127.0.0.1", "50001", "50000", "50003", "50002", "short".toCharArray()));
	}

	@Test
	void rejectsEmptyHost() {
		assertThrows(InvalidSettingsException.class, () -> ConnectionSettings.parse("  ", "50001", "50000", "50003", "50002", GOOD_PASS));
	}
}
