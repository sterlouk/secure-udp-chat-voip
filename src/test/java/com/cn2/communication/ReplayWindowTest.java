package com.cn2.communication;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class ReplayWindowTest {

	@Test
	void acceptsIncreasingSequence() {
		ReplayWindow w = new ReplayWindow();
		for (long seq = 0; seq < 200; seq++) assertTrue(w.checkAndMark(seq));
	}

	@Test
	void rejectsDuplicates() {
		ReplayWindow w = new ReplayWindow();
		assertTrue(w.checkAndMark(5));
		assertFalse(w.checkAndMark(5));
	}

	@Test
	void acceptsOutOfOrderWithinWindowOnce() {
		ReplayWindow w = new ReplayWindow();
		assertTrue(w.checkAndMark(10));
		assertTrue(w.checkAndMark(8));
		assertTrue(w.checkAndMark(9));
		assertFalse(w.checkAndMark(8));
		assertFalse(w.checkAndMark(9));
	}

	@Test
	void rejectsPacketsOlderThanWindow() {
		ReplayWindow w = new ReplayWindow();
		assertTrue(w.checkAndMark(100));
		assertTrue(w.checkAndMark(100 - ReplayWindow.SIZE + 1)); // oldest still inside
		assertFalse(w.checkAndMark(100 - ReplayWindow.SIZE)); // just outside
	}

	@Test
	void largeJumpResetsHistory() {
		ReplayWindow w = new ReplayWindow();
		assertTrue(w.checkAndMark(1));
		assertTrue(w.checkAndMark(1_000));
		assertFalse(w.checkAndMark(1_000));
		assertTrue(w.checkAndMark(999));
		assertFalse(w.checkAndMark(1));
	}

	@Test
	void rejectsNegativeSequence() {
		assertFalse(new ReplayWindow().checkAndMark(-1));
	}
}
