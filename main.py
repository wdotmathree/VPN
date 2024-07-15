import ike
import esp

from threading import Thread
from typing import Any

misoq: list[tuple[bytes, tuple[str, int]]] = [] # Message queue for IKE messages from esp.py
mosiq: list[dict[str, Any]] = [] # Message queue for message from ike.py
thing: dict[bytes, tuple[list[bytes]]] = {}

t1 = Thread(target=ike.main, args=(misoq, mosiq, thing), daemon=True)
t2 = Thread(target=esp.main, args=(misoq, mosiq, thing), daemon=True)

t1.start()
t2.start()
t1.join()
t2.join()
