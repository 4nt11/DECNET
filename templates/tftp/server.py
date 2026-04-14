#!/usr/bin/env python3
"""
TFTP server (UDP 69).
Parses RRQ (read) and WRQ (write) requests, logs filename and transfer mode,
then responds with an error packet. Logs all requests as JSON.
"""

import asyncio
import os
import struct
from decnet_logging import syslog_line, write_syslog_file, forward_syslog

NODE_NAME = os.environ.get("NODE_NAME", "tftpserver")
SERVICE_NAME   = "tftp"
LOG_TARGET = os.environ.get("LOG_TARGET", "")

# TFTP opcodes
_RRQ = 1
_WRQ = 2
_ERROR = 5

# TFTP Error packet: opcode(2) + error_code(2) + error_msg + NUL
def _error_pkt(code: int, msg: str) -> bytes:
    return struct.pack(">HH", _ERROR, code) + msg.encode() + b"\x00"




def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


class TFTPProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self._transport = None

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data: bytes, addr):
        if len(data) < 4:
            return
        opcode = struct.unpack(">H", data[:2])[0]
        if opcode in (_RRQ, _WRQ):
            # Filename and mode are NUL-terminated strings after the opcode
            parts = data[2:].split(b"\x00")
            filename = parts[0].decode(errors="replace") if parts else ""
            mode = parts[1].decode(errors="replace") if len(parts) > 1 else ""
            _log(
                "request",
                src=addr[0],
                src_port=addr[1],
                op="RRQ" if opcode == _RRQ else "WRQ",
                filename=filename,
                mode=mode,
            )
            self._transport.sendto(_error_pkt(2, "Access violation"), addr)
        else:
            _log("unknown_opcode", src=addr[0], opcode=opcode, data=data[:32].hex())

    def error_received(self, exc):
        pass


async def main():
    _log("startup", msg=f"TFTP server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        TFTPProtocol, local_addr=("0.0.0.0", 69)  # nosec B104
    )
    try:
        await asyncio.sleep(float("inf"))
    finally:
        transport.close()


if __name__ == "__main__":
    asyncio.run(main())
