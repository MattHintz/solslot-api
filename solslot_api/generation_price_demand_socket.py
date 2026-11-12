"""Local fixed-message client for the separately privileged price collector."""
import asyncio,json,os,stat
from pathlib import Path

MESSAGE=b'{"op":"refresh"}'
STATUS_MESSAGE=b'{"op":"status"}'
MAX_REPLY=32768


class PriceDemandSocketCollector:
    def __init__(self,path,*,expected_uid=0,expected_gid):
        self.path=Path(path)
        if (not self.path.is_absolute() or type(expected_uid)is not int or expected_uid<0
                or type(expected_gid)is not int or expected_gid<0):
            raise ValueError('CURRENT_PRICE_SOCKET_CONFIGURATION_INVALID')
        self.uid,self.gid=expected_uid,expected_gid

    def _check(self):
        parent=self.path.parent
        if parent.is_symlink() or not parent.is_dir() or self.path.is_symlink():
            raise ValueError('CURRENT_PRICE_SOCKET_PATH_INVALID')
        directory=parent.stat();sock=self.path.stat()
        if (directory.st_uid!=self.uid or directory.st_mode&0o022
                or not stat.S_ISSOCK(sock.st_mode) or sock.st_uid!=self.uid or sock.st_gid!=self.gid
                or sock.st_mode&0o007 or sock.st_mode&0o600!=0o600):
            raise ValueError('CURRENT_PRICE_SOCKET_PERMISSIONS_INVALID')

    async def _exchange(self,message):
        if message not in (MESSAGE,STATUS_MESSAGE):
            raise ValueError('CURRENT_PRICE_SOCKET_OPERATION_INVALID')
        self._check()
        reader,writer=await asyncio.open_unix_connection(str(self.path))
        try:
            writer.write(message);await writer.drain()
            if not writer.can_write_eof():raise ValueError('CURRENT_PRICE_SOCKET_HALF_CLOSE_REQUIRED')
            writer.write_eof()
            chunks=bytearray()
            while True:
                part=await reader.read(min(4096,MAX_REPLY+1-len(chunks)))
                if not part:break
                chunks.extend(part)
                if len(chunks)>MAX_REPLY:raise ValueError('CURRENT_PRICE_SOCKET_RESPONSE_INVALID')
            raw=bytes(chunks)
            if not raw:raise ValueError('CURRENT_PRICE_SOCKET_RESPONSE_INVALID')
            value=json.loads(raw)
            if not isinstance(value,dict):raise ValueError('CURRENT_PRICE_SOCKET_RESPONSE_INVALID')
            return value
        finally:
            writer.close()
            await writer.wait_closed()

    async def __call__(self):
        value=await self._exchange(MESSAGE)
        if (value.get('state')!='SIGNED_PRICE_READY'
                or type(value.get('sequence'))is not int or value['sequence']<=0
                or type(value.get('validUntil'))is not int or value['validUntil']<=0):
            raise ValueError('CURRENT_PRICE_COLLECTOR_UNAVAILABLE')
        return value

    async def status(self,*,now,required_until):
        if type(now)is not int or required_until!=now+300:
            raise ValueError('CURRENT_PRICE_STATUS_BINDING_INVALID')
        return await self._exchange(STATUS_MESSAGE)
