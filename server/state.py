import threading
import time
import logging
COMMIT = "COMMIT"
REVEAL = "REVEAL"
ENDED = "ENDED"

STATE_SEQUENCE = [COMMIT, REVEAL, ENDED]

# Time (seconds) for each state
STATE_DURATIONS = {
    COMMIT: 120,       # 10 minute
    REVEAL: 600,       # 10 minute
}

# --- Logging setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger("server")

class ServerState:
    def __init__(self):
        self.state = COMMIT
        self.lock = threading.Lock()
        self.state_start_time = time.time()
        self._start_state_timer()

    def _start_state_timer(self):
        def advance_state():
            for state in STATE_SEQUENCE[:-1]:  # Don't transition after ENDED
                time.sleep(STATE_DURATIONS.get(state, 0))
                with self.lock:
                    if self.state == state:
                        idx = STATE_SEQUENCE.index(state)
                        logger.info(f"{self.state} state ended, transitioning to {STATE_SEQUENCE[idx + 1]}")
                        self.state = STATE_SEQUENCE[idx + 1]
                        self.state_start_time = time.time()
            # After all, set to ENDED
            with self.lock:
                self.state = ENDED
        threading.Thread(target=advance_state, daemon=True).start()

    def get_state(self):
        with self.lock:
            return self.state

    def get_state_time_left(self):
        with self.lock:
            if self.state == ENDED:
                return 0
            elapsed = time.time() - self.state_start_time
            return max(0, STATE_DURATIONS.get(self.state, 0) - elapsed)
