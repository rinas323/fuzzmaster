import sys
import time

class ProgressBar:
    """Simple console progress bar for FuzzMaster scans."""
    def __init__(self, total):
        self.total = total
        self.current = 0
        self.start_time = time.time()
        self.last_print = 0

    def update(self, completed):
        self.current = completed
        now = time.time()
        # Limit print frequency
        if now - self.last_print > 0.2 or self.current == self.total:
            percent = (self.current / self.total) * 100 if self.total else 100
            bar = ('#' * int(percent // 2)).ljust(50)
            elapsed = now - self.start_time
            sys.stdout.write(f"\r[{bar}] {self.current}/{self.total} ({percent:.1f}%) Elapsed: {elapsed:.1f}s")
            sys.stdout.flush()
            self.last_print = now

    def finish(self):
        self.update(self.total)
        print() 