import ike
import esp

from threading import Thread
from typing import *

misoq: list[tuple[bytes, tuple[str, int]]] = [] # Message queue for IKE messages from esp.py
mosiq: list[dict[str, Any]] = [] # Message queue for message from ike.py
thing: dict[bytes, tuple[list[bytes]]] = {}

Thread(target=ike.main, args=(misoq, mosiq, thing)).start()
Thread(target=esp.main, args=(misoq, mosiq, thing)).start()
