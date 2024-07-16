import ike
import esp
import forward
from queue import Queue

from threading import Thread
from typing import Any

misoq: Queue[tuple[bytes, tuple[str, int]]] = Queue() # Message queue for IKE messages from esp.py
mosiq: Queue[dict[str, Any]] = Queue() # Message queue for message from ike.py
thing: dict[bytes, tuple[Queue[bytes]]] = {}
forwardq: Queue[tuple[bytes, int, bytes]] = Queue() # Message queue for messages from esp.py to forward.py

t1 = Thread(target=ike.main, args=(misoq, mosiq), daemon=True)
t2 = Thread(target=esp.main, args=(misoq, mosiq, thing, forwardq), daemon=True)
t3 = Thread(target=forward.main, args=(thing, forwardq), daemon=True)

t1.start()
t2.start()
t3.start()
t1.join()
t2.join()
t3.join()
