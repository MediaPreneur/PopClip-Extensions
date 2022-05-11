import os
import re
import webbrowser
import sys

input = os.environ['POPCLIP_TEXT']
version = os.environ['POPCLIP_OPTION_VERSION']
text = unicode(input, "utf-8")
pattern = "(\\d+\\s)?(\\w+?\\.?\\s\\d+:\\d+)(.\\d+)?(\\d+(.\\d+)?)*"
verses = re.findall(pattern, input)
verseList = [''.join(map(str, item)) for item in verses]

def chunks(list, listSize):
    return [list[i:i + listSize] for i in range(0, len(list), listSize)]

verseChunks = chunks(verseList, 25)

verseListsToUrls = [', '.join(map(str, item)) for item in verseChunks]
if not verseListsToUrls:
	sys.exit(1)

for item in verseListsToUrls:
    webbrowser.open(
        f"http://www.biblegateway.com/passage/?search={item}&version={version}&interface=print"
    )