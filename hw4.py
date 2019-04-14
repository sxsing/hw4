import logging
import re
import sys
from bs4 import BeautifulSoup
from queue import Queue, PriorityQueue
from urllib import parse, request

logging.basicConfig(level=logging.DEBUG, filename='output.log', filemode='w')
visitlog = logging.getLogger('visited')
extractlog = logging.getLogger('extracted')


def parse_links(root, html):
    soup = BeautifulSoup(html, 'html.parser')
    for link in soup.find_all('a'):
        href = link.get('href')
        if href:
            text = link.string
            if not text:
                text = ''
            text = re.sub('\s+', ' ', text).strip()
            yield (parse.urljoin(root, link.get('href')), text)


def parse_links_sorted(root, html):
    # TODO: implement
    pq = PriorityQueue()
    for link in parse_links(root, html):
        pq.put((-len(link[1]), link))
    result = []
    while not pq.empty():
        result.append(pq.get()[1])
        print(pq.get()[1])
    return result


def get_links(url):
    res = request.urlopen(url)
    return list(parse_links(url, res.read()))


def get_nonlocal_links(url):
    '''Get a list of links on the page specificed by the url,
    but only keep non-local links and non self-references.
    Return a list of (link, title) pairs, just like get_links()'''

    # TODO: implement
    links = get_links(url)
    filtered = [link for link in links if not urls_same_host(link[0], url)]
    return filtered

def urls_same_host(url1, url2):
    return parse.urlparse(url1).hostname == parse.urlparse(url2).hostname

def content_match(content_type, wanted_list):
    for wanted_content in wanted_list:
        if wanted_content in content_type :
            return True
    return False

def crawl(root, wanted_content=[], within_domain=True):
    '''Crawl the url specified by `root`.
    `wanted_content` is a list of content types to crawl
    `within_domain` specifies whether the crawler should limit itself to the domain of `root`
    '''
    # TODO: implement

    pq = PriorityQueue()
    pq.put((0, root))

    visited = []
    extracted = []
    url_set = set()


    while not pq.empty():
        url = pq.get()[1]
        try:
            req = request.urlopen(url, timeout=5)
            html = req.read()

            visited.append(url)
            visitlog.debug(url)

            if len(visited) > 100:
                break

            if len(wanted_content) == 0 or (req.headers['Content-Type'] and content_match(req.headers['Content-Type'], wanted_content)):
                for ex in extract_information(url, html):
                    extracted.append(ex)
                    extractlog.debug(ex)

            for link, title in parse_links(url, html):
                if (link not in url_set) and (urls_same_host(root, link) or not within_domain):
                    print(len(visited), pq.qsize(), link)
                    url_set.add(link)
                    pq.put((-len(title), link))

        except Exception as e:
            print(e, url)

    return visited, extracted


def extract_information(address, html):
    '''Extract contact information from html, returning a list of (url, category, content) pairs,
    where category is one of PHONE, ADDRESS, EMAIL'''

    # TODO: implement
    results = []
    for match in re.findall('(?:\([0-9]{3}\)-?|[0-9]{3}[-.])[0-9]{3}[-.][0-9]{4}', str(html)):
        results.append((address, 'PHONE', match))
    for match in re.findall('\w+@[a-zA-Z_]+?\.[a-zA-Z]{2,3}', str(html)):
        results.append((address, 'EMAIL', match))
    for match in re.findall('(?:[A-Z][a-z]*\s)*(?:[A-Z][a-z]*)+,\s*(?:AK|Alaska|AL|Alabama|AR|Arkansas|AZ|Arizona|CA|California|CO|Colorado|CT|Connecticut|DC|Washington\sDC|Washington\D\.C\.|DE|Delaware|FL|Florida|GA|Georgia|GU|Guam|HI|Hawaii|IA|Iowa|ID|Idaho|IL|Illinois|IN|Indiana|KS|Kansas|KY|Kentucky|LA|Louisiana|MA|Massachusetts|MD|Maryland|ME|Maine|MI|Michigan|MN|Minnesota|MO|Missouri|MS|Mississippi|MT|Montana|NC|North\sCarolina|ND|North\sDakota|NE|New\sEngland|NH|New\sHampshire|NJ|New\sJersey|NM|New\sMexico|NV|Nevada|NY|New\sYork|OH|Ohio|OK|Oklahoma|OR|Oregon|PA|Pennsylvania|RI|Rhode\sIsland|SC|South\sCarolina|SD|South\sDakota|TN|Tennessee|TX|Texas|UT|Utah|VA|Virginia|VI|Virgin\sIslands|VT|Vermont|WA|Washington|WI|Wisconsin|WV|West\sVirginia|WY|Wyoming)\s+\d{5}(?:-\d{4})?', str(html)):
        results.append((address, 'ADDRESS', match))
    return results


def writelines(filename, data):
    with open(filename, 'w') as fout:
        for d in data:
            print(d, file=fout)


def main():
    site = sys.argv[1]

    links = get_links(site)
    writelines('links.txt', links)

    nonlocal_links = get_nonlocal_links(site)
    writelines('nonlocal.txt', nonlocal_links)

    visited, extracted = crawl(site)
    writelines('visited.txt', visited)
    writelines('extracted.txt', extracted)


if __name__ == '__main__':
    main()