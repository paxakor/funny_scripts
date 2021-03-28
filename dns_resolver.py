import argparse
import collections
import copy
import io
import ipaddress
import logging
import random
import socket
import time

import tornado.httpserver
import tornado.web


################################################################################

def now():
    return time.time()


def prnt(*args, **kwargs):
    if 1:
        print(*args, **kwargs)


class DnsRecord:
    def __init__(self, domain, ip=None, ttl=None):
        self.domain = domain
        self.ip = ip
        self.ttl = now() + ttl


class CacheStorage:
    def __init__(self, max_size=1024):
        self.storage = collections.defaultdict(list)
        self.max_size = max_size
        self.size = 0

    def get(self, domain):
        self._cleanup()
        return self.storage.get(domain)

    def put(self, record):
        self._cleanup()
        if self.size < self.max_size:
            self.storage[record.domain].append(record)
            self.size += 1

    def _cleanup(self):
        for key in self.storage:
            actual_records = list()
            for rec in self.storage[key]:
                if rec.ttl < now():
                    self.size -= 1
                else:
                    actual_records.append(rec)

            self.storage[key] = actual_records


CACHE_STORAGE = None


ROOT_SERVERS = [
    ("a.root-servers.net", "198.41.0.4", "2001:503:ba3e::2:30"),
    ("b.root-servers.net", "199.9.14.201", "2001:500:200::b"),
    ("c.root-servers.net", "192.33.4.12", "2001:500:2::c"),
    ("d.root-servers.net", "199.7.91.13", "2001:500:2d::d"),
    ("e.root-servers.net", "192.203.230.10", "2001:500:a8::e"),
    ("f.root-servers.net", "192.5.5.241", "2001:500:2f::f"),
    ("g.root-servers.net", "192.112.36.4", "2001:500:12::d0d"),
    ("h.root-servers.net", "198.97.190.53", "2001:500:1::53"),
    ("i.root-servers.net", "192.36.148.17", "2001:7fe::53"),
    ("j.root-servers.net", "192.58.128.30", "2001:503:c27::2:30"),
    ("k.root-servers.net", "193.0.14.129", "2001:7fd::1"),
    ("l.root-servers.net", "199.7.83.42", "2001:500:9f::42"),
    ("m.root-servers.net", "202.12.27.33", "2001:dc3::35"),
]

################################################################################


def to_int(bs):
    return int.from_bytes(bs, 'big')


def to_bytes(number, l):
    return number.to_bytes(l, 'big')


class DnsRequest:
    def __init__(self, domain_name):
        self.id = random.randint(1, 2**16) - 1
        prnt("request id:", self.id)

        query_count = 1

        self.request = io.BytesIO()
        self.request.write(to_bytes(self.id, 2))        # id
        self.request.write(bytearray.fromhex("01 00"))  # flags
        self.request.write(to_bytes(query_count, 2))    # query count
        self.request.write(to_bytes(0, 2))              # answer count
        self.request.write(to_bytes(0, 2))              # ns-answer count
        self.request.write(to_bytes(0, 2))              # other-answer count

        # qname
        for part in domain_name.strip().split('.'):
            self.request.write(to_bytes(len(part), 1))  # length
            self.request.write(part.encode('ascii'))

        self.request.write(to_bytes(0, 1))  # end qname

        self.request.write(to_bytes(1, 2))  # qtype = 1 (A)
        self.request.write(to_bytes(1, 2))  # qclass = 1


class DnsResponse:
    def _parse_domain_name_parts(self, response, l_first=None):
        domain_parts = list()
        while True:
            l = to_int(response.read(1))

            if l == 0:
                break
            elif (l & (3 << 6)):
                t = to_int(response.read(1))
                offset = ((l % (3 << 6)) << 8) + t
                yield self._parse_domain_name(self.data[offset:])
                break
            else:
                part = response.read(l)
                yield part.decode('ascii')

    def _parse_domain_name(self, response):
        if isinstance(response, bytes):
            response = io.BytesIO(response)

        return '.'.join(self._parse_domain_name_parts(response))

    def _parse_small_section(self, response):
        domain = self._parse_domain_name(response).lower()
        _type = to_int(response.read(2))
        _class = to_int(response.read(2))
        return (domain, _type, _class)

    def _parse_section(self, response):
        domain, _type, _class = self._parse_small_section(response)
        ttl = to_int(response.read(4))
        rdlen = to_int(response.read(2))
        rdata = response.read(rdlen)

        if _type == 1:
            # ipv4
            if self.ip_version == '6':
                return None
            rdata = '.'.join(map(str, rdata))

            CACHE_STORAGE.put(DnsRecord(domain, ip=rdata, ttl=ttl))
        elif _type == 2:
            # domain name of authoritative name server
            rdata = self._parse_domain_name(rdata).lower()
        elif _type == 28:
            # ipv6
            if self.ip_version == '4':
                return None
            rdata = str(ipaddress.IPv6Address(rdata))

            CACHE_STORAGE.put(DnsRecord(domain, ip=rdata, ttl=ttl))
        else:
            raise DnsResolverError('Not implemented for type={}'.format(_type))

        return (domain, _type, _class, ttl, rdata)

    def _parse_sections(self, response, sections_count):
        sections = list()
        for _ in range(sections_count):
            entry = self._parse_section(response)
            if entry:
                sections.append(entry)

        return sections

    def __init__(self, data, ip_version='6'):
        self.data = data
        self.ip_version = ip_version

        response = io.BytesIO(self.data)
        self.id = to_int(response.read(2))
        self.flags = response.read(2)
        self.query_count = to_int(response.read(2))
        self.answer_count = to_int(response.read(2))
        self.ns_answer_count = to_int(response.read(2))
        self.other_answer_count = to_int(response.read(2))

        prnt("self.id =", self.id)
        prnt("query_count =", self.query_count)
        prnt("answer_count =", self.answer_count)
        prnt("ns_answer_count =", self.ns_answer_count)
        prnt("other_answer_count =", self.other_answer_count)

        self.queries = list()
        for _ in range(self.query_count):
            self.queries.append(self._parse_small_section(response))

        self.answers = self._parse_sections(response, self.answer_count)
        self.ns_answers = self._parse_sections(response, self.ns_answer_count)
        self.other_answers = self._parse_sections(response, self.other_answer_count)

        prnt("answers:\n" + '\n'.join(map(str, self.answers)))
        prnt("ns_answers:\n" + '\n'.join(map(str, self.ns_answers)))
        prnt("other_answers:\n" + '\n'.join(map(str, self.other_answers)))

    def has_answer(self):
        return self.answer_count > 0

    def get_answer(self):
        return [ans[4] for ans in self.answers]

    def select_next_dns_server(self):
        ids = list(range(len(self.ns_answers)))
        random.shuffle(ids)
        for pos in ids:
            fqdn = self.ns_answers[pos][4]
            for ans in self.other_answers:
                if fqdn == ans[0]:
                    return fqdn, ans[4]
        return fqdn, fqdn


################################################################################


class Singleton:
    def __new__(cls):
        return cls._instance

    @classmethod
    def __getattr__(cls, name):
        return getattr(cls._instance, name)

    @classmethod
    def init(cls):
        cls._instance = None


class DnsResolverLogger(Singleton):
    @classmethod
    def init(cls, filename):
        logFormatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
        fileHandler = logging.handlers.WatchedFileHandler(filename)  # reopens after logrotate
        fileHandler.setFormatter(logFormatter)
        cls._instance = logging.getLogger(cls.__name__)
        cls._instance.addHandler(fileHandler)


class PrettyException(Exception):
    def __init__(self, message):
        super(PrettyException, self).__init__('{}({})'.format(self.__class__.__name__, message))


class DnsResolverError(PrettyException):
    pass


class DnsResolverHandler(tornado.web.RequestHandler):

    def answer_with_http_code(self, code, reason=None):
        self.set_status(code, reason=reason)
        if reason:
            self.write(reason)
            if not reason.endswith('\n'):
                self.write('\n')

    def make_request(self, domain_name, ip_version):
        root_server = random.choice(ROOT_SERVERS)
        dns_server_name = root_server[0]
        if ip_version == '4':
            dns_server_addr = root_server[1]
        else:
            dns_server_addr = root_server[2]

        route = list()
        while True:
            DnsResolverLogger().debug('Requesting %s from %s', domain_name, dns_server_name)

            route.append((dns_server_name, dns_server_addr))

            message = DnsRequest(domain_name).request.getvalue()
            socket_type = socket.AF_INET if '.' in dns_server_addr else socket.AF_INET6
            sock = socket.socket(socket_type, socket.SOCK_DGRAM)
            sock.sendto(message, (dns_server_addr, 53))
            data, sender = sock.recvfrom(512)
            response = DnsResponse(data, ip_version)

            if response.has_answer():
                return route, response.get_answer()
            else:
                dns_server_name, dns_server_addr = response.select_next_dns_server()
                if dns_server_addr is None:
                    self.answer_with_http_code(500, "Can not find next DNS server :(")
                    break

        return None, None

    def get(self):
        domain_name = self.get_argument('domain')
        ip_version = self.get_argument('ipv', 'any')
        trace = (self.get_argument('trace', '0') in ['true', '1'])

        if not domain_name:
            self.answer_with_http_code(400, 'Invalid domain')

        if ip_version not in ['4', '6', 'any']:
            self.answer_with_http_code(400, "Invalid ipv. Use '4', '6' or 'any'")

        cached_record = CACHE_STORAGE.get(domain_name)
        if cached_record:
            ip = [rec.ip for rec in cached_record]

        if (not cached_record) or trace:
            route, ip = self.make_request(domain_name, ip_version)
            if trace and route:
                self.write("Trace:\n")
                for i in range(len(route)):
                    self.write(f"{i}:\t{route[i][0]} ({route[i][1]})\n")
                self.write("\n")

        if not ip:
            self.write(f"Can not find IPv{ip_version} address of {domain_name}!\n")
        else:
            self.write(f"Addresses of {domain_name}: {', '.join(ip)}\n")


################################################################################


class PingHandler(tornado.web.RequestHandler):
    def get(self):
        self.write('pong')


################################################################################


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', default=80)
    parser.add_argument('-s', '--cache-size', default=1024)
    args = parser.parse_args()

    global CACHE_STORAGE
    CACHE_STORAGE = CacheStorage(max_size=args.cache_size)

    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s'
    )

    DnsResolverLogger.init('dns_resolver.log')

    app = tornado.web.Application([
        (r'/ping',                          PingHandler),
        (r'/get-a-records',                 DnsResolverHandler),
    ])

    server = tornado.httpserver.HTTPServer(app, xheaders=True)
    server.bind(args.port)
    server.start(1)
    tornado.ioloop.IOLoop.current().start()


if __name__ == '__main__':
    main()
