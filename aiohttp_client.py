# Test module for asyncio and aiohttp
import asyncio
import aiohttp
import json
import logging
import time


class HTTPRestClient(object):
    def __init__(self, limit):
        conn = aiohttp.TCPConnector(limit=limit)
        self.session = aiohttp.ClientSession(connector=conn)

    def close(self):
        self.session.close()

    @asyncio.coroutine
    def do_get(self, url, params=None, timeout=None):
        with aiohttp.Timeout(timeout):
            resp = yield from self.session.get(url, params=params)
            try:
                # Any actions that may lead to error:
                return (yield from resp.json())
            except Exception as e:
                # .close() on exception.
                resp.close()
                raise e
            finally:
                # .release() otherwise to return connection into free connection pool.
                # It's ok to release closed response:
                # https://github.com/KeepSafe/aiohttp/blob/master/aiohttp/client_reqrep.py#L664
                yield from resp.release()

    @asyncio.coroutine
    def do_post(self, url, data, timeout=None):
        with aiohttp.Timeout(timeout):
            resp = yield from self.session.post(url, data=data)
            try:
                return (yield from resp.json())
            except Exception as e:
                resp.close()
                raise e
            finally:
                yield from resp.release()

    @asyncio.coroutine
    def do_put(self, url, data, timeout=None):
        with aiohttp.Timeout(timeout):
            resp = yield from self.session.put(url, data=data)
            try:
                return (yield from resp.json())
            except Exception as e:
                resp.close()
                raise e
            finally:
                yield from resp.release()

    @asyncio.coroutine
    def do_delete(self, url, timeout=None):
        with aiohttp.Timeout(timeout):
            resp = yield from self.session.delete(url)
            try:
                return (yield from resp.json())
            except Exception as e:
                resp.close()
                raise e
            finally:
                yield from resp.release()


def run_tests(rest_cli):
    for i in range(0,100):
        loop.create_task(rest_cli.do_get('http://httpbin.org/get', {'seq':i}))
        #loop.create_task(rest_cli.do_get('https://api.github.com/events', {'seq':i}))

loop = asyncio.get_event_loop()
loop.set_debug(True)

if __name__ == '__main__':
    try:
        rest_cli = HTTPRestClient(20)
        run_tests(rest_cli)
        loop.run_forever()
    except KeyboardInterrupt:
        print('\nInterrupted\n')
    finally:
        # next two lines are required for actual aiohttp resource cleanup
        loop.stop()
        rest_cli.close()
        #loop.run_forever()
        loop.close()
