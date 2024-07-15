import ike
import esp
from queue import Queue

from threading import Thread
from typing import Any

misoq: Queue[tuple[bytes, tuple[str, int]]] = Queue() # Message queue for IKE messages from esp.py
mosiq: Queue[dict[str, Any]] = Queue() # Message queue for message from ike.py
thing: dict[bytes, tuple[Queue[bytes]]] = {}

t1 = Thread(target=ike.main, args=(misoq, mosiq, thing), daemon=True)
t2 = Thread(target=esp.main, args=(misoq, mosiq, thing), daemon=True)

t1.start()
t2.start()
t1.join()
t2.join()
