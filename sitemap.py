import sys
import os
import BeautifulSoup
from BeautifulSoup import SoupStrainer
import certifi
import graphviz
from graphviz import Digraph
import urllib2


page_seen = []
dot = Digraph(comment='Site map')


def find_links(url):
	local_pages = []
	try:
		source = urllib2.urlopen(url)
	except urllib2.URLError:
		return ([],[])
	parse_links = BeautifulSoup.BeautifulSoup(source)

	for link in parse_links.findAll('a', href=True):
		if link['href'] not in page_seen \
			and not link['href'].startswith("http") \
			and not link['href'].startswith("mailto"):
			local_pages.append(link['href'])
			page_seen.append(link['href'])
		else:
			continue
	pics = []
	for image in parse_links.findAll(itemprop='img'):
		pics.append(image)
		return pics
	
	return (local_pages, pics)



def spider(local_pages):
	for link in local_pages:
		link_url = sys.argv[1] + link
		dot.node(link, link)
		new_links, pics = find_links(link_url)
		for new_link in new_links:
			dot.edge(link, new_link)
		spider(new_links)

spider(['/'])

dot.render("test.gv", view=True)
